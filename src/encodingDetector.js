/**
 * Encoding Attack Detector (ESP v1.3)
 * 
 * Detects encoded payloads that hide prompt injection attempts:
 * - Base64 (with heuristic validation to reduce false positives)
 * - ROT13
 * - Hex-encoded strings
 * - Quoted-printable encoding
 * - URL encoding
 * 
 * Each encoding is decoded and the decoded content is checked
 * for injection patterns using the PatternMatcher.
 */

const { PatternMatcher } = require('./patternMatcher');

// Base64: minimum 20 chars, well-formed, with decode check
const BASE64_PATTERN = /[A-Za-z0-9+/]{20,}={0,2}/g;

// Hex-encoded strings (sequences of hex pairs)
const HEX_PATTERN = /(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}){5,}/g;

// Quoted-printable: =XX where XX are hex digits
const QP_PATTERN = /=(?:[0-9A-Fa-f]{2}){1}(?=\r?\n|=)/g;

// URL-encoded: %XX sequences
const URL_ENCODED_PATTERN = /(?:%[0-9A-Fa-f]{2}){3,}/g;

// ROT13 indicators (common words that appear ROT13-encoded)
const ROT13_COMMON_WORDS = [
  'vtabeng',  // "ignore"
  'cebgrpg',  // "protect"
  'fhccbj',   // "subject"
  'vafgehpg', // "instruction"
  'flfgrz',   // "system"
  'cebcevrg', // "private"
  'nqqrevff', // "address"
];

/**
 * Decode Base64 string
 * @param {string} str - Base64 string
 * @returns {string|null} - Decoded string or null if invalid
 */
function decodeBase64(str) {
  try {
    // Validate: must be proper base64 length (multiple of 4 after padding)
    const cleaned = str.replace(/\s/g, '');
    if (cleaned.length % 4 > 2) return null;
    
    const decoded = Buffer.from(cleaned, 'base64').toString('utf-8');
    
    // Heuristic: decoded text should be mostly printable ASCII
    const printableRatio = decoded.split('').filter(c => {
      const code = c.charCodeAt(0);
      return (code >= 32 && code < 127) || code === 10 || code === 13;
    }).length / decoded.length;
    
    if (printableRatio < 0.7) return null;
    
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode ROT13 string
 * @param {string} str - ROT13-encoded string
 * @returns {string} - Decoded string
 */
function decodeRot13(str) {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : 97;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

/**
 * Decode hex string (\x41 or %41 format)
 * @param {string} str - Hex-encoded string
 * @returns {string} - Decoded string
 */
function decodeHex(str) {
  try {
    // Handle \xNN format
    let decoded = str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    
    // Handle %NN format
    decoded = decoded.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    
    return decoded;
  } catch {
    return '';
  }
}

/**
 * Decode quoted-printable string
 * @param {string} str - QP-encoded string
 * @returns {string} - Decoded string
 */
function decodeQuotedPrintable(str) {
  try {
    // =XX → byte, = at end of line → soft line break
    let decoded = str.replace(/=\r?\n/g, ''); // soft line breaks
    decoded = decoded.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    return decoded;
  } catch {
    return '';
  }
}

/**
 * Decode URL-encoded string
 * @param {string} str - URL-encoded string
 * @returns {string} - Decoded string
 */
function decodeUrlEncoded(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return '';
  }
}

/**
 * Detect encoding attacks in text
 * @param {string} text - Text to scan
 * @param {Object} options - Detection options
 * @returns {Object} - { flags, decodedPayloads, severity }
 */
function detectEncodingAttacks(text, options = {}) {
  const {
    checkBase64 = true,
    checkHex = true,
    checkQuotedPrintable = true,
    checkUrlEncoded = true,
    checkRot13 = true,
    maxDecodeLength = 10000,
    patternMatcher = null,
  } = options;

  const matcher = patternMatcher || new PatternMatcher();
  const flags = [];
  const decodedPayloads = [];
  let maxSeverity = 'clean';

  const severityOrder = ['low', 'medium', 'high', 'critical'];
  const updateSeverity = (sev) => {
    if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {
      maxSeverity = sev;
    }
  };

  // Check Base64
  if (checkBase64) {
    BASE64_PATTERN.lastIndex = 0;
    let match;
    while ((match = BASE64_PATTERN.exec(text)) !== null) {
      const decoded = decodeBase64(match[0]);
      if (decoded && decoded.length > 0 && decoded.length < maxDecodeLength) {
        // Check if decoded content contains injection patterns
        const scanResult = matcher.scan(decoded);
        if (!scanResult.clean) {
          flags.push({
            type: 'base64_injection',
            severity: scanResult.severity,
            encodedSample: match[0].substring(0, 50) + '...',
            decodedSample: decoded.substring(0, 200),
            injectionFlags: scanResult.flags.map(f => f.id),
            position: match.index,
          });
          updateSeverity(scanResult.severity);
          decodedPayloads.push({
            encoding: 'base64',
            original: match[0],
            decoded,
            injections: scanResult.flags,
          });
        } else if (decoded.length > 50) {
          // Long base64 that decodes to readable text but no injection — low severity
          flags.push({
            type: 'base64_suspicious',
            severity: 'low',
            encodedSample: match[0].substring(0, 50) + '...',
            decodedSample: decoded.substring(0, 100),
            position: match.index,
          });
          updateSeverity('low');
        }
      }
    }
  }

  // Check Hex-encoded
  if (checkHex) {
    HEX_PATTERN.lastIndex = 0;
    let match;
    while ((match = HEX_PATTERN.exec(text)) !== null) {
      const decoded = decodeHex(match[0]);
      if (decoded && decoded.length > 3) {
        const scanResult = matcher.scan(decoded);
        if (!scanResult.clean) {
          flags.push({
            type: 'hex_injection',
            severity: scanResult.severity,
            encodedSample: match[0].substring(0, 50) + '...',
            decodedSample: decoded.substring(0, 200),
            injectionFlags: scanResult.flags.map(f => f.id),
            position: match.index,
          });
          updateSeverity(scanResult.severity);
          decodedPayloads.push({
            encoding: 'hex',
            original: match[0],
            decoded,
            injections: scanResult.flags,
          });
        }
      }
    }
  }

  // Check Quoted-Printable
  if (checkQuotedPrintable) {
    // First, try to find QP-encoded sections
    const qpRegex = /((?:=[0-9A-Fa-f]{2}[^\s]*)+)/g;
    qpRegex.lastIndex = 0;
    let match;
    while ((match = qpRegex.exec(text)) !== null) {
      if (match[0].length < 10) continue; // too short
      const decoded = decodeQuotedPrintable(match[0]);
      if (decoded && decoded !== match[0] && decoded.length > 3) {
        const scanResult = matcher.scan(decoded);
        if (!scanResult.clean) {
          flags.push({
            type: 'qp_injection',
            severity: scanResult.severity,
            encodedSample: match[0].substring(0, 50) + '...',
            decodedSample: decoded.substring(0, 200),
            injectionFlags: scanResult.flags.map(f => f.id),
            position: match.index,
          });
          updateSeverity(scanResult.severity);
          decodedPayloads.push({
            encoding: 'quoted-printable',
            original: match[0],
            decoded,
            injections: scanResult.flags,
          });
        }
      }
    }
  }

  // Check URL-encoded
  if (checkUrlEncoded) {
    URL_ENCODED_PATTERN.lastIndex = 0;
    let match;
    while ((match = URL_ENCODED_PATTERN.exec(text)) !== null) {
      const decoded = decodeUrlEncoded(match[0]);
      if (decoded && decoded !== match[0] && decoded.length > 3) {
        const scanResult = matcher.scan(decoded);
        if (!scanResult.clean) {
          flags.push({
            type: 'url_encoded_injection',
            severity: scanResult.severity,
            encodedSample: match[0].substring(0, 50) + '...',
            decodedSample: decoded.substring(0, 200),
            injectionFlags: scanResult.flags.map(f => f.id),
            position: match.index,
          });
          updateSeverity(scanResult.severity);
          decodedPayloads.push({
            encoding: 'url',
            original: match[0],
            decoded,
            injections: scanResult.flags,
          });
        }
      }
    }
  }

  // Check ROT13 (heuristic: look for common ROT13-encoded injection words)
  if (checkRot13) {
    const rot13Decoded = decodeRot13(text);
    if (rot13Decoded !== text) {
      // Check for ROT13 common injection words
      for (const word of ROT13_COMMON_WORDS) {
        if (text.toLowerCase().includes(word)) {
          // This word in the text is a known word in ROT13 form
          // The full ROT13 decode might reveal injection patterns
          const scanResult = matcher.scan(rot13Decoded);
          if (!scanResult.clean) {
            flags.push({
              type: 'rot13_injection',
              severity: scanResult.severity,
              rot13Sample: text.substring(0, 100),
              decodedSample: rot13Decoded.substring(0, 200),
              injectionFlags: scanResult.flags.map(f => f.id),
            });
            updateSeverity(scanResult.severity);
            decodedPayloads.push({
              encoding: 'rot13',
              original: text,
              decoded: rot13Decoded,
              injections: scanResult.flags,
            });
            break; // one ROT13 flag is enough
          }
        }
      }
    }
  }

  return {
    flags,
    decodedPayloads,
    severity: maxSeverity,
    hasAttacks: flags.some(f => f.type.endsWith('_injection')),
  };
}

/**
 * Check a specific string for encoding attacks
 * @param {string} text - Text to check
 * @param {Object} options - Options
 * @returns {boolean} - Whether encoding attacks were detected
 */
function hasEncodingAttack(text, options = {}) {
  const result = detectEncodingAttacks(text, options);
  return result.hasAttacks;
}

module.exports = {
  detectEncodingAttacks,
  hasEncodingAttack,
  decodeBase64,
  decodeRot13,
  decodeHex,
  decodeQuotedPrintable,
  decodeUrlEncoded,
  BASE64_PATTERN,
  HEX_PATTERN,
  QP_PATTERN,
  URL_ENCODED_PATTERN,
  ROT13_COMMON_WORDS,
};