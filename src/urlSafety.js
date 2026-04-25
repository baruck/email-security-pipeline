/**
 * URL Safety Check (ESP v1.4)
 * 
 * Flags suspicious URLs in email content that may deliver prompt payloads:
 * - URL shorteners (bit.ly, tinyurl, etc.)
 * - Known malicious URL patterns
 * - Suspicious query parameters (prompt, inject, cmd, exec, etc.)
 * - Data URIs (can embed arbitrary content)
 * - IPs as hosts (no domain name)
 * - Excessive subdomains
 * - Punycode/IDN homograph domains
 */

// Known URL shortener domains
const URL_SHORTENER_DOMAINS = [
  'bit.ly', 'j.mp', 'bitly.com',
  'tinyurl.com', 'tiny.cc',
  't.co',
  'ow.ly', 'ht.ly',
  'is.gd', 'v.gd',
  'buff.ly',
  'adf.ly',
  'goo.gl', 'g.co',
  'cli.gs',
  'tr.im',
  'shorte.st',
  'lnkd.in',
  'db.tt',
  'qr.ae',
  'rb.gy',
  'cutt.ly',
  'shorturl.at',
  'rebrand.ly',
  'smarturl.it',
  'bl.ink',
  'lc.chat',
  'soo.gd',
  's2r.co',
  'clck.ru',
];

// Suspicious query parameter names that may carry prompt payloads
const SUSPICIOUS_QUERY_PARAMS = [
  'prompt', 'inject', 'payload', 'cmd', 'exec', 'eval',
  'system', 'admin', 'override', 'instruction', 'directive',
  'command', 'run', 'execute', 'render', 'template',
  'q', 'query', 'input', 'msg', 'message', 'content',
  'role', 'persona', 'character', 'identity',
];

// Suspicious URL path patterns (no /g flag — recreated on each use to avoid state issues)
const SUSPICIOUS_PATH_PATTERNS = [
  /\/(?:prompt|inject|payload|cmd|exec|eval|system|admin|override|instruction|directive)\b/i,
  /\/(?:api|v\d+)\/(?:chat|completion|generate|run|execute)\b/i,
];

// Data URI pattern
const DATA_URI_PATTERN = /data:(?:text|application)\/(?:html|javascript|json)[;,]/i;

// IP-as-host pattern (http://1.2.3.4/path)
const IP_HOST_PATTERN = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/\S*)?/i;

// Punycode pattern (xn-- prefix indicates IDN)
const PUNYCODE_PATTERN = /https?:\/\/[a-z0-9\-]*xn--[a-z0-9\-]+/i;

// Excessive subdomain pattern (5+ subdomains)
const EXCESSIVE_SUBDOMAIN_PATTERN = /https?:\/\/(?:[a-z0-9\-]+\.){5,}[a-z]{2,}/i;

// General URL pattern (with /g for use with exec in scanUrlsInText)
const URL_PATTERN = /https?:\/\/[^\s<>"']+/gi;

/**
 * Parse URL into components for analysis
 * @param {string} url - URL to parse
 * @returns {Object} - Parsed URL components
 */
function parseUrl(url) {
  try {
    const parsed = new URL(url);
    return {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      pathname: parsed.pathname,
      search: parsed.search,
      searchParams: Object.fromEntries(parsed.searchParams.entries()),
      hash: parsed.hash,
      isIp: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname),
      subdomainCount: parsed.hostname.split('.').length - 1,
    };
  } catch {
    return null;
  }
}

/**
 * Check a URL for safety concerns
 * @param {string} url - URL to check
 * @param {Object} options - Check options
 * @returns {Object} - { safe, flags, riskScore }
 */
function checkUrlSafety(url, options = {}) {
  const {
    checkShorteners = true,
    checkSuspiciousParams = true,
    checkSuspiciousPaths = true,
    checkDataUris = true,
    checkIpHosts = true,
    checkPunycode = true,
    checkExcessiveSubdomains = true,
  } = options;

  const flags = [];
  let riskScore = 0;

  // Check data URIs
  if (checkDataUris && /data:(?:text|application)\/(?:html|javascript|json)[;,]/i.test(url)) {
    flags.push({
      type: 'data_uri',
      severity: 'critical',
      description: 'Data URI can embed arbitrary content including script injection payloads',
      url: url.substring(0, 100),
    });
    riskScore += 80;
  }

  // Check IP-as-host
  if (checkIpHosts) {
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/\S*)?/i.test(url)) {
      flags.push({
        type: 'ip_host',
        severity: 'high',
        description: 'URL uses an IP address instead of a domain name — common in phishing and malware delivery',
        url: url.substring(0, 100),
      });
      riskScore += 60;
    }
  }

  // Parse URL for further checks
  const parsed = parseUrl(url);
  if (parsed) {
    // Check URL shorteners
    if (checkShorteners) {
      const isShortened = URL_SHORTENER_DOMAINS.some(domain => 
        parsed.hostname === domain || parsed.hostname.endsWith('.' + domain)
      );
      if (isShortened) {
        flags.push({
          type: 'url_shortener',
          severity: 'medium',
          description: 'Shortened URL — destination cannot be verified before clicking',
          domain: parsed.hostname,
        });
        riskScore += 30;
      }
    }

    // Check suspicious query parameters
    if (checkSuspiciousParams && parsed.searchParams) {
      for (const [key, value] of Object.entries(parsed.searchParams)) {
        const lowerKey = key.toLowerCase();
        if (SUSPICIOUS_QUERY_PARAMS.includes(lowerKey)) {
          flags.push({
            type: 'suspicious_query_param',
            severity: 'high',
            description: `Query parameter "${key}" may carry a prompt injection payload`,
            param: key,
            valuePreview: (value || '').substring(0, 50),
          });
          riskScore += 50;
        }
        // Also check parameter values for injection content
        if (value && typeof value === 'string') {
          const lowerValue = value.toLowerCase();
          if (lowerValue.includes('ignore') && lowerValue.includes('instruction')) {
            flags.push({
              type: 'injection_in_query_value',
              severity: 'critical',
              description: 'Query parameter value contains prompt injection pattern',
              param: key,
              valuePreview: value.substring(0, 100),
            });
            riskScore += 80;
          }
        }
      }
    }

    // Check suspicious path patterns
    if (checkSuspiciousPaths) {
      for (const pattern of SUSPICIOUS_PATH_PATTERNS) {
        if (pattern.test(parsed.pathname)) {
          flags.push({
            type: 'suspicious_path',
            severity: 'high',
            description: `URL path contains suspicious pattern: ${parsed.pathname}`,
            path: parsed.pathname,
          });
          riskScore += 40;
          break;
        }
      }
    }

    // Check punycode
    if (checkPunycode) {
      if (parsed.hostname.includes('xn--')) {
        flags.push({
          type: 'punycode_domain',
          severity: 'medium',
          description: 'Punycode/IDN domain — may be a homograph attack',
          domain: parsed.hostname,
        });
        riskScore += 35;
      }
    }

    // Check excessive subdomains
    if (checkExcessiveSubdomains && parsed.subdomainCount >= 5) {
      flags.push({
        type: 'excessive_subdomains',
        severity: 'low',
        description: `URL has ${parsed.subdomainCount} subdomains — may be obfuscation`,
        domain: parsed.hostname,
      });
      riskScore += 15;
    }
  }

  // Clamp risk score
  riskScore = Math.min(riskScore, 100);

  return {
    safe: flags.length === 0,
    flags,
    riskScore,
    riskLevel: riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : riskScore > 0 ? 'low' : 'clean',
  };
}

/**
 * Scan email content for suspicious URLs
 * @param {string} text - Text to scan
 * @param {Object} options - Scanning options
 * @returns {Object} - { flags, urls, urlResults, maxRiskScore }
 */
function scanUrlsInText(text, options = {}) {
  const {
    maxUrls = 50,
    ...checkOptions
  } = options;

  const allFlags = [];
  const urlResults = [];
  const urls = [];
  let maxRiskScore = 0;

  URL_PATTERN.lastIndex = 0;
  let match;
  let urlCount = 0;

  while ((match = URL_PATTERN.exec(text)) !== null && urlCount < maxUrls) {
    const url = match[0];
    urls.push(url);
    urlCount++;

    const result = checkUrlSafety(url, checkOptions);
    urlResults.push({
      url: url.substring(0, 200),
      ...result,
    });

    if (result.flags.length > 0) {
      allFlags.push(...result.flags.map(f => ({
        ...f,
        url: url.substring(0, 100),
        position: match.index,
      })));
    }

    if (result.riskScore > maxRiskScore) {
      maxRiskScore = result.riskScore;
    }
  }

  // Also check for data URIs (which don't match the http pattern)
  const dataUriRegex = /data:(?:text|application)\/(?:html|javascript|json)[;,][^\s]+/gi;
  while ((match = dataUriRegex.exec(text)) !== null && urlCount < maxUrls) {
    const url = match[0];
    const result = checkUrlSafety(url, checkOptions);
    urlResults.push({
      url: url.substring(0, 200),
      ...result,
    });
    if (result.flags.length > 0) {
      allFlags.push(...result.flags);
    }
    if (result.riskScore > maxRiskScore) {
      maxRiskScore = result.riskScore;
    }
  }

  return {
    flags: allFlags,
    urls,
    urlResults,
    maxRiskScore,
    hasHighRisk: maxRiskScore >= 70,
    hasMediumRisk: maxRiskScore >= 40,
  };
}

module.exports = {
  checkUrlSafety,
  scanUrlsInText,
  parseUrl,
  URL_SHORTENER_DOMAINS,
  SUSPICIOUS_QUERY_PARAMS,
  SUSPICIOUS_PATH_PATTERNS,
  DATA_URI_PATTERN,
  IP_HOST_PATTERN,
  PUNYCODE_PATTERN,
  URL_PATTERN,
};