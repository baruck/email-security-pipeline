/**
 * Email Security Pipeline
 * 
 * Orchestrates Layers 1→2→3 for both inbound and outbound email processing.
 * This is the main entry point for the module.
 */

const { sanitizeHtml, sanitizePlainText } = require('./sanitizer');
const { PatternMatcher } = require('./patternMatcher');
const { OutboundReviewer } = require('./reviewer');

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
  }

  /**
   * Process an inbound email (Layers 1 + 2)
   * @param {string} rawContent - Raw email content (HTML or plain text)
   * @param {Object} options - Processing options
   * @returns {Object} - { sanitizedText, flags, stats, quarantined }
   */
  processInbound(rawContent, options = {}) {
    const {
      isHtml = true,
      minSeverity = 'low',
      quarantineOnCritical = true,
    } = options;

    // Layer 1: Sanitize
    let sanitizeResult;
    if (isHtml) {
      sanitizeResult = sanitizeHtml(rawContent, options);
    } else {
      sanitizeResult = sanitizePlainText(rawContent, options);
    }

    // Layer 2: Pattern matching
    const scanResult = this.patternMatcher.scan(sanitizeResult.sanitizedText, {
      minSeverity,
      quarantineOnCritical,
    });

    // Determine quarantine status
    const quarantined = scanResult.requiresReview;

    // If quarantined, call the handler
    if (quarantined) {
      this.quarantineHandler({
        type: 'inbound',
        originalContent: rawContent,
        sanitizedText: sanitizeResult.sanitizedText,
        flags: scanResult.flags,
        severity: scanResult.severity,
        stats: sanitizeResult.stats,
      });
    }

    return {
      sanitizedText: sanitizeResult.sanitizedText,
      flags: scanResult.flags,
      severity: scanResult.severity,
      stats: sanitizeResult.stats,
      quarantined,
      safeForLLM: !quarantined,
    };
  }

  /**
   * Process an outbound email (Layer 3)
   * @param {string} replyText - The reply text to review
   * @param {string} originalEmail - Original inbound email (for context)
   * @param {Object} options - Review options
   * @returns {Object} - { approved, reply, flags, quarantined }
   */
  async processOutbound(replyText, originalEmail = '', options = {}) {
    const result = await this.reviewer.review(replyText, originalEmail, options);

    // If quarantined, call the handler
    if (result.quarantined) {
      this.quarantineHandler({
        type: 'outbound',
        replyText,
        originalEmail,
        flags: result.flags,
      });
    }

    return result;
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
    };
  }
}

/**
 * Default quarantine handler — logs to console and saves to file
 */
function defaultQuarantineHandler({ type, flags, sanitizedText, severity }) {
  const timestamp = new Date().toISOString();
  console.warn(`[QUARANTINE ${type.toUpperCase()}] ${timestamp} - Severity: ${severity}`);
  console.warn(`  Flags: ${flags.map(f => `${f.id}(${f.severity})`).join(', ')}`);
  
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