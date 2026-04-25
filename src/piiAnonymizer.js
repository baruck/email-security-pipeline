/**
 * PII Anonymizer (ESP v1.2)
 * 
 * Replaces detected PII with reversible placeholders in email input,
 * and restores original values on output. This protects personal data
 * from being exposed to LLMs during processing.
 * 
 * Flow: original → anonymize → LLM → deanonymize → final output
 */

const { detectPII } = require('./piiDetector');

// Placeholder format: [TYPE_INDEX] e.g. [EMAIL_1], [PHONE_2], [NIF_1]
const PLACEHOLDER_REGEX = /\[([A-Z]+)_(\d+)\]/g;

/**
 * Create an anonymizer instance
 * @param {Object} options - Anonymization options
 * @returns {Object} - { anonymize, deanonymize, getMap }
 */
function createPIIAnonymizer(options = {}) {
  const {
    placeholderFormat = (type, index) => `[${type}_${index}]`,
    detectOptions = {},
  } = options;

  // Internal mapping: placeholder → original value
  const placeholderMap = new Map();
  // Counter per type for unique placeholders
  const typeCounters = {};

  /**
   * Anonymize text by replacing PII with placeholders
   * @param {string} text - Text containing PII
   * @returns {Object} - { anonymizedText, map, piiFound }
   */
  function anonymize(text) {
    // Reset state for fresh anonymization
    placeholderMap.clear();
    for (const key of Object.keys(typeCounters)) {
      delete typeCounters[key];
    }

    const findings = detectPII(text, detectOptions);

    if (findings.length === 0) {
      return {
        anonymizedText: text,
        map: {},
        piiFound: 0,
      };
    }

    // Sort findings by position (reverse order for safe replacement)
    const sorted = [...findings].sort((a, b) => b.start - a.start);

    let anonymizedText = text;

    for (const finding of sorted) {
      const type = finding.type.toUpperCase();
      typeCounters[type] = (typeCounters[type] || 0) + 1;
      const index = typeCounters[type];

      const placeholder = placeholderFormat(type, index);

      placeholderMap.set(placeholder, {
        original: finding.value,
        type: finding.type,
        confidence: finding.confidence,
      });

      anonymizedText =
        anonymizedText.substring(0, finding.start) +
        placeholder +
        anonymizedText.substring(finding.end);
    }

    // Build serializable map
    const mapObj = {};
    for (const [placeholder, data] of placeholderMap) {
      mapObj[placeholder] = data;
    }

    return {
      anonymizedText,
      map: mapObj,
      piiFound: findings.length,
    };
  }

  /**
   * Deanonymize text by restoring original PII values
   * @param {string} text - Text with placeholders
   * @param {Object} map - Optional map override (uses internal map by default)
   * @returns {Object} - { deanonymizedText, restored, unreplaced }
   */
  function deanonymize(text, map = null) {
    const useMap = map || Object.fromEntries(placeholderMap);
    let deanonymizedText = text;
    let restored = 0;
    let unreplaced = 0;

    PLACEHOLDER_REGEX.lastIndex = 0;
    const placeholders = text.match(PLACEHOLDER_REGEX) || [];

    for (const placeholder of placeholders) {
      if (useMap[placeholder]) {
        deanonymizedText = deanonymizedText.replace(
          placeholder,
          useMap[placeholder].original
        );
        restored++;
      } else {
        unreplaced++;
      }
    }

    return {
      deanonymizedText,
      restored,
      unreplaced,
    };
  }

  /**
   * Get the current placeholder map
   */
  function getMap() {
    return Object.fromEntries(placeholderMap);
  }

  /**
   * Check if text contains any placeholders
   */
  function hasPlaceholders(text) {
    PLACEHOLDER_REGEX.lastIndex = 0;
    return PLACEHOLDER_REGEX.test(text);
  }

  return {
    anonymize,
    deanonymize,
    getMap,
    hasPlaceholders,
  };
}

/**
 * Standalone anonymization (one-shot, no instance needed)
 * @param {string} text - Text to anonymize
 * @param {Object} options - Options
 * @returns {Object} - { anonymizedText, map, deanonymize }
 */
function anonymizePII(text, options = {}) {
  const anonymizer = createPIIAnonymizer(options);
  const result = anonymizer.anonymize(text);

  return {
    anonymizedText: result.anonymizedText,
    map: result.map,
    piiFound: result.piiFound,
    deanonymize: (outputText, map) => anonymizer.deanonymize(outputText, map || result.map),
  };
}

module.exports = {
  createPIIAnonymizer,
  anonymizePII,
  PLACEHOLDER_REGEX,
};