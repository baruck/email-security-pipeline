/**
 * PII Detector (ESP v1.2)
 * 
 * Detects personally identifiable information in email content:
 * - Email addresses
 * - Phone numbers (international, Portuguese, US formats)
 * - Names (common patterns)
 * - Physical addresses (Portuguese and general patterns)
 * - Portuguese tax IDs (CPF/NIF, NISS, CC)
 * 
 * Returns structured results with type, value, and position info.
 */

// Email pattern
const EMAIL_PATTERN = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

// Phone patterns (international, Portuguese, US, general)
const PHONE_PATTERNS = [
  // Portuguese: +351 912345678, +351 912 345 678, 912345678
  /(?:\+351[\s\-]?)?9\d{2}[\s\-]?\d{3}[\s\-]?\d{3}/g,
  // Portuguese landline: +351 2XXX XXXX
  /(?:\+351[\s\-]?)?2\d{2}[\s\-]?\d{3}[\s\-]?\d{3}/g,
  // US: (555) 123-4567, 555-123-4567, +1 555 123 4567
  /(?:\+1[\s\-]?)?(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-]?)\d{3}[\s\-]?\d{4}/g,
  // International general: +XX XXX XXX XXXX
  /\+\d{1,3}[\s\-]?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}/g,
];

// Portuguese NIF (9 digits, mod 11 validation)
const NIF_PATTERN = /\b(?:NIF|nif|NIPC|nipc)[:\s]*(\d{9})\b|\b(\d{9})\s*(?:NIF|nif|NIPC|nipc)\b|\bPT\d{9}\b/g;

// Portuguese CC (Citizen Card) - 8 digits + check char + 2 digits + check char
const CC_PATTERN = /\b\d{8}\s?\d\s?[A-Z]\s?\d{2}/g;

// Portuguese NISS (Social Security) - 11 digits starting with 1 or 2
const NISS_PATTERN = /\b[12]\d{10}\b/g;

// Common name patterns in email signatures and formal correspondence
const NAME_PATTERNS = [
  // Portuguese formal: "Sr. João Silva", "Sra. Maria Santos", "Dr. Pedro Costa"
  /(?:Sr\.|Sra\.|Sr\.a|Dr\.|Dra\.|Eng\.|Arq\.|Prof\.|Profa\.)\s+([A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]+){0,3})/g,
  // General: "Name: João Silva", "Nome: ..."
  /(?:Name|Nome|Nombre)\s*:\s*([A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]+){0,3})/gi,
  // Signature-style: at end of email, "Cumprimentos,\nJoão Silva"
  /(?:Com os melhores cumprimentos|Best regards|Atenciosamente|Cumprimentos|Saudações),?\s*\n\s*([A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]+){0,3})/g,
];

// Portuguese address patterns
const ADDRESS_PATTERNS = [
  // "Rua da X, Nº 123", "Av. de Y, 45", "Largo do Z, 12"
  /(?:Rua|Av\.?|Avenida|Largo|Praça|Praceta|Travessa|Calçada|Estrada|Rotunda|Caminho)\s+(?:da|de|do|das|dos|d')?\s*[A-ZÀ-ÿ][a-zà-ÿ\s]+,?\s*(?:N\.?º?|n\.?º?|nº|n\.)?\s*\d+/gi,
  // Postal codes: "1234-567 Lisboa", "4400-123 Porto"
  /\b\d{4}-\d{3}\s+[A-ZÀ-ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-ÿ][a-zà-ÿ]+)*/g,
  // "Morada: Rua X"
  /(?:Morada|Address|Endereço|Dirección)\s*:\s*.+/gi,
];

/**
 * Validate a Portuguese NIF using mod-11 check
 * @param {string} nif - 9-digit NIF to validate
 * @returns {boolean} - Whether the NIF is valid
 */
function validateNIF(nif) {
  if (!/^\d{9}$/.test(nif)) return false;
  
  const validFirstDigits = [1, 2, 3, 5, 6, 7, 8, 9];
  if (!validFirstDigits.includes(parseInt(nif[0]))) return false;
  
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += parseInt(nif[i]) * (9 - i);
  }
  const checkDigit = 11 - (sum % 11);
  const expected = checkDigit >= 10 ? 0 : checkDigit;
  
  return parseInt(nif[8]) === expected;
}

/**
 * Detect PII in text
 * @param {string} text - Text to scan for PII
 * @param {Object} options - Detection options
 * @returns {Array} - Array of detected PII items
 */
function detectPII(text, options = {}) {
  const {
    detectEmails = true,
    detectPhones = true,
    detectNames = true,
    detectAddresses = true,
    detectTaxIds = true,
    minConfidence = 'medium', // low, medium, high
  } = options;

  const findings = [];

  // Detect email addresses
  if (detectEmails) {
    EMAIL_PATTERN.lastIndex = 0;
    let match;
    while ((match = EMAIL_PATTERN.exec(text)) !== null) {
      findings.push({
        type: 'email',
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        confidence: 'high',
      });
    }
  }

  // Detect phone numbers
  if (detectPhones) {
    for (const pattern of PHONE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        // Deduplicate: skip if overlapping with existing finding
        const overlaps = findings.some(f => 
          (match.index >= f.start && match.index < f.end) ||
          (match.index + match[0].length > f.start && match.index + match[0].length <= f.end)
        );
        if (!overlaps) {
          findings.push({
            type: 'phone',
            value: match[0],
            start: match.index,
            end: match.index + match[0].length,
            confidence: 'high',
          });
        }
      }
    }
  }

  // Detect names
  if (detectNames) {
    for (const pattern of NAME_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const name = match[1] || match[0];
        findings.push({
          type: 'name',
          value: name.trim(),
          start: match.index,
          end: match.index + match[0].length,
          confidence: 'medium',
        });
      }
    }
  }

  // Detect addresses
  if (detectAddresses) {
    for (const pattern of ADDRESS_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        findings.push({
          type: 'address',
          value: match[0].trim(),
          start: match.index,
          end: match.index + match[0].length,
          confidence: 'medium',
        });
      }
    }
  }

  // Detect tax IDs
  if (detectTaxIds) {
    // NIF
    NIF_PATTERN.lastIndex = 0;
    let match;
    while ((match = NIF_PATTERN.exec(text)) !== null) {
      const nif = match[1] || match[2] || match[0].replace('PT', '');
      if (validateNIF(nif.replace(/\s/g, ''))) {
        findings.push({
          type: 'nif',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: 'high',
        });
      }
    }

    // CC
    CC_PATTERN.lastIndex = 0;
    while ((match = CC_PATTERN.exec(text)) !== null) {
      findings.push({
        type: 'cc',
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        confidence: 'medium',
      });
    }

    // NISS (only if it looks like a social security number in context)
    NISS_PATTERN.lastIndex = 0;
    while ((match = NISS_PATTERN.exec(text)) !== null) {
      // Avoid false positives on random 11-digit numbers
      const context = text.substring(Math.max(0, match.index - 30), match.index + match[0].length + 30);
      if (/NISS|SS|segurança\s+social|social\s+security/i.test(context)) {
        findings.push({
          type: 'niss',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: 'medium',
        });
      }
    }
  }

  // Filter by confidence level
  const confidenceOrder = ['low', 'medium', 'high'];
  const minIndex = confidenceOrder.indexOf(minConfidence);

  return findings.filter(f => confidenceOrder.indexOf(f.confidence) >= minIndex);
}

module.exports = {
  detectPII,
  validateNIF,
  EMAIL_PATTERN,
  PHONE_PATTERNS,
  NIF_PATTERN,
  CC_PATTERN,
  NISS_PATTERN,
  NAME_PATTERNS,
  ADDRESS_PATTERNS,
};