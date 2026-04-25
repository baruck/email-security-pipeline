/**
 * Email Security Pipeline
 * 
 * Orchestrates Layers 1→2→3 for both inbound and outbound email processing.
 * Now includes: canary tokens, PII anonymization, encoding detection, URL safety.
 * This is the main entry point for the module.
 */

const { sanitizeHtml, sanitizePlainText } = require('./sanitizer');
const { PatternMatcher } = require('./patternMatcher');
const { OutboundReviewer } = require('./reviewer');
const { createCanaryGuard } = require('./canaryWord');
const { createPIIAnonymizer } = require('./piiAnonymizer');
const { detectEncodingAttacks } = require('./encodingDetector');
const { scanUrlsInText } = require('./urlSafety');

class EmailSecurityPipeline {
  constructor(options = {}) {
    this.patternMatcher = new PatternMatcher(options.blocklistPath);
    this.reviewer = new OutboundReviewer({
      model: options.reviewModel || 'gpt-4o',
      strict: options.strict !== false,
      apiEndpoint: options.apiEndpoint || null,
      apiKey: options.apiKey || null,
    });
    this.quarantineHandler = options.quarantineHandler || defaultQuarantineHandler;

    // ESP v1.1: Canary tokens
    this.canaryGuard = createCanaryGuard(options.canaryOptions || {});

    // ESP v1.2: PII anonymization
    this.piiAnonymizer = createPIIAnonymizer(options.piiOptions || {});

    // ESP v1.3: Encoding attack detection (enabled by default)
    this.enableEncodingDetection = options.enableEncodingDetection !== false;

    // ESP v1.4: URL safety check (enabled by default)
    this.enableUrlSafety = options.enableUrlSafety !== false;
  }

  /**
   * Process an inbound email (Layers 1 + 2 + v1.2-1.4)
   * @param {string} rawContent - Raw email content (HTML or plain text)
   * @param {Object} options - Processing options
   * @returns {Object} - { sanitizedText, flags, stats, quarantined, piiMap, canaryTokens }
   */
  processInbound(rawContent, options = {}) {
    const {
      isHtml = true,
      minSeverity = 'low',
      quarantineOnCritical = true,
      anonymizePII = true,
      checkEncoding = true,
      checkUrls = true,
    } = options;

    const allFlags = [];
    let maxSeverity = 'clean';
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const updateSeverity = (sev) => {
      if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {
        maxSeverity = sev;
      }
    };

    // Layer 1: Sanitize
    let sanitizeResult;
    if (isHtml) {
      sanitizeResult = sanitizeHtml(rawContent, options);
    } else {
      sanitizeResult = sanitizePlainText(rawContent, options);
    }

    let text = sanitizeResult.sanitizedText;

    // ESP v1.3: Encoding attack detection (before pattern matching, on sanitized text)
    if (checkEncoding && this.enableEncodingDetection) {
      const encodingResult = detectEncodingAttacks(text, {
        patternMatcher: this.patternMatcher,
      });
      if (encodingResult.flags.length > 0) {
        allFlags.push(...encodingResult.flags);
        updateSeverity(encodingResult.severity);
      }
    }

    // Layer 2: Pattern matching
    const scanResult = this.patternMatcher.scan(text, {
      minSeverity,
      quarantineOnCritical,
    });
    if (scanResult.flags.length > 0) {
      allFlags.push(...scanResult.flags);
      updateSeverity(scanResult.severity);
    }

    // ESP v1.4: URL safety check
    if (checkUrls && this.enableUrlSafety) {
      const urlResult = scanUrlsInText(text);
      if (urlResult.flags.length > 0) {
        allFlags.push(...urlResult.flags);
        // URL flags contribute to severity based on risk level
        if (urlResult.hasHighRisk) updateSeverity('high');
        else if (urlResult.hasMediumRisk) updateSeverity('medium');
        else if (urlResult.flags.length > 0) updateSeverity('low');
      }
    }

    // ESP v1.2: PII anonymization (after all scanning, before LLM consumption)
    let piiResult = null;
    if (anonymizePII) {
      piiResult = this.piiAnonymizer.anonymize(text);
      if (piiResult.piiFound > 0) {
        text = piiResult.anonymizedText;
      }
    }

    // Determine quarantine status
    const quarantined = (scanResult.requiresReview) ||
      (maxSeverity === 'critical' && quarantineOnCritical) ||
      (maxSeverity === 'high' && this.reviewer.strict);

    // If quarantined, call the handler
    if (quarantined) {
      this.quarantineHandler({
        type: 'inbound',
        originalContent: rawContent,
        sanitizedText: text,
        flags: allFlags,
        severity: maxSeverity,
        stats: sanitizeResult.stats,
      });
    }

    return {
      sanitizedText: text,
      flags: allFlags,
      severity: maxSeverity,
      stats: sanitizeResult.stats,
      quarantined,
      safeForLLM: !quarantined,
      piiMap: piiResult ? piiResult.map : null,
      piiFound: piiResult ? piiResult.piiFound : 0,
      encodingFlags: allFlags.filter(f => f.type && f.type.includes('_injection') || f.type === 'base64_suspicious'),
      urlFlags: allFlags.filter(f => f.type && ['url_shortener', 'suspicious_query_param', 'injection_in_query_value', 'data_uri', 'ip_host', 'punycode_domain', 'excessive_subdomains', 'suspicious_path'].includes(f.type)),
    };
  }

  /**
   * Process an outbound email (Layer 3 + v1.1 canary check + v1.2 deanonymize)
   * @param {string} replyText - The reply text to review
   * @param {string} originalEmail - Original inbound email (for context)
   * @param {Object} options - Review options
   * @returns {Object} - { approved, reply, flags, quarantined }
   */
  async processOutbound(replyText, originalEmail = '', options = {}) {
    const {
      checkCanaryLeak = true,
      deanonymizePII = true,
      piiMap = null,
    } = options;

    let text = replyText;
    const extraFlags = [];

    // ESP v1.1: Canary token leak check
    if (checkCanaryLeak) {
      const canaryResult = this.canaryGuard.check(text);
      if (canaryResult.leaked) {
        extraFlags.push({
          type: 'canary_leak',
          severity: 'critical',
          description: 'System prompt canary token detected in output — prompt may have been leaked',
          leakedTokens: canaryResult.leakedTokens,
          leakCount: canaryResult.leakCount,
        });
      }
    }

    // Layer 3: Outbound review
    const result = await this.reviewer.review(text, originalEmail, options);

    // Combine flags
    const allFlags = [...result.flags, ...extraFlags];
    let approved = result.approved;
    let quarantined = result.quarantined;

    // Canary leak = automatic quarantine
    if (extraFlags.length > 0) {
      approved = false;
      quarantined = true;
    }

    // ESP v1.2: Deanonymize PII
    let finalText = text;
    if (deanonymizePII && piiMap) {
      const deAnonResult = this.piiAnonymizer.deanonymize(text, piiMap);
      finalText = deAnonResult.deanonymizedText;
    }

    // If quarantined, call the handler
    if (quarantined) {
      this.quarantineHandler({
        type: 'outbound',
        replyText: finalText,
        originalEmail,
        flags: allFlags,
      });
    }

    return {
      approved,
      reply: finalText,
      flags: allFlags,
      quarantined,
      reviewedAt: result.reviewedAt,
    };
  }

  /**
   * Inject canary tokens into a system prompt
   * @param {string} systemPrompt - The system prompt to protect
   * @returns {Object} - { injectedPrompt, tokens }
   */
  injectCanaryTokens(systemPrompt) {
    return this.canaryGuard.inject(systemPrompt);
  }

  /**
   * Get the PII anonymization map for the last inbound processing
   * @returns {Object} - The PII placeholder map
   */
  getPIIMap() {
    return this.piiAnonymizer.getMap();
  }

  /**
   * Deanonymize text using a PII map
   * @param {string} text - Text with PII placeholders
   * @param {Object} map - PII map (uses internal map if not provided)
   * @returns {Object} - { deanonymizedText, restored, unreplaced }
   */
  deanonymizePII(text, map = null) {
    return this.piiAnonymizer.deanonymize(text, map);
  }

  /**
   * Reload the blocklist (for when SecurityExpert updates it)
   */
  reloadBlocklist(blocklistPath) {
    return this.patternMatcher.reload(blocklistPath);
  }

  /**
   * Get pipeline status summary
   */
  getStatus() {
    return {
      patternMatcher: this.patternMatcher.getSummary(),
      reviewer: {
        model: this.reviewer.model,
        strict: this.reviewer.strict,
        apiConfigured: !!(this.reviewer.apiEndpoint && this.reviewer.apiKey),
      },
      canaryGuard: {
        activeTokens: this.canaryGuard.getActiveTokens().length,
      },
      encodingDetection: this.enableEncodingDetection,
      urlSafety: this.enableUrlSafety,
    };
  }
}

/**
 * Default quarantine handler — logs to console and saves to file
 */
function defaultQuarantineHandler({ type, flags, sanitizedText, severity }) {
  const timestamp = new Date().toISOString();
  console.warn(`[QUARANTINE ${type.toUpperCase()}] ${timestamp} - Severity: ${severity}`);
  console.warn(`  Flags: ${flags.map(f => `${f.id || f.type}(${f.severity})`).join(', ')}`);
  
  // In production, this would save to a quarantine directory and alert
  return {
    quarantined: true,
    timestamp,
    type,
    severity,
    flagCount: flags.length,
  };
}

module.exports = { EmailSecurityPipeline, defaultQuarantineHandler };