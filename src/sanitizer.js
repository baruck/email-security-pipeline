/**
 * Layer 1: HTML → Plain Text Sanitizer
 * 
 * Strips all HTML, removes invisible text, normalizes Unicode,
 * decodes encoded content, and produces LLM-safe plain text.
 */

const { convert } = require('html-to-text');
const unidecode = require('unidecode');

// Patterns that indicate invisible or hidden content
const INVISIBLE_PATTERNS = [
  /display\s*:\s*none/gi,
  /visibility\s*:\s*hidden/gi,
  /opacity\s*:\s*0/gi,
  /font-size\s*:\s*0/gi,
  /color\s*:\s*[^;]*background/gi, // same color as background
  /position\s*:\s*absolute\s*;\s*left\s*:\s*-?\d{4,}/gi, // offscreen
  /height\s*:\s*0/gi,
  /width\s*:\s*0/gi,
  /overflow\s*:\s*hidden\s*;\s*(?:text-indent|line-height|font-size)\s*:\s*-?\d{3,}/gi,
];

// Zero-width and control characters to strip
const ZERO_WIDTH_CHARS = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u180E]/g;

// RTL override characters
const RTL_OVERRIDES = /[\u202D\u202E\u2066-\u2069]/g;

// Homoglyph normalization map (common confusables)
const HOMOGLYPH_MAP = {
  '\u0430': 'a', // Cyrillic а → Latin a
  '\u0435': 'e', // Cyrillic е → Latin e
  '\u043E': 'o', // Cyrillic о → Latin o
  '\u0440': 'p', // Cyrillic р → Latin p
  '\u0441': 'c', // Cyrillic с → Latin c
  '\u0443': 'y', // Cyrillic у → Latin y
  '\u0456': 'i', // Cyrillic і → Latin i
  '\u0458': 'j', // Cyrillic ј → Latin j
  '\u04BB': 'h', // Cyrillic һ → Latin h
  '\u0570': 'h', // Armenian հ → Latin h
};

/**
 * Remove invisible HTML elements (display:none, etc.)
 */
function removeInvisibleContent(html) {
  let cleaned = html;
  
  // Remove elements with invisible styling
  for (const pattern of INVISIBLE_PATTERNS) {
    // Remove entire tags that match invisible patterns
    cleaned = cleaned.replace(
      new RegExp(`<[^>]*style=["'][^"']*${pattern.source}[^"']*["'][^>]*>[\\s\\S]*?<\\/[^>]+>`, 'gi'),
      ''
    );
  }
  
  // Remove <style> blocks entirely
  cleaned = cleaned.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
  
  // Remove script blocks
  cleaned = cleaned.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
  
  // Remove HTML comments (can hide content)
  cleaned = cleaned.replace(/<!--[\s\S]*?-->/g, '');
  
  return cleaned;
}

/**
 * Normalize Unicode to catch homoglyphs and confusables
 */
function normalizeUnicode(text) {
  // Apply NFKC normalization
  let normalized = text.normalize('NFKC');
  
  // Replace known homoglyphs
  for (const [from, to] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.replace(new RegExp(from, 'g'), to);
  }
  
  return normalized;
}

/**
 * Strip zero-width characters and RTL overrides
 */
function stripHiddenCharacters(text) {
  return text
    .replace(ZERO_WIDTH_CHARS, '')
    .replace(RTL_OVERRIDES, '')
    .replace(/\u200B/g, '') // zero-width space
    .replace(/\uFEFF/g, '') // BOM
    .replace(/\u00AD/g, '') // soft hyphen
    .replace(/\u180E/g, ''); // Mongolian vowel separator
}

/**
 * Main sanitization function
 * @param {string} rawHtml - Raw HTML email content
 * @param {Object} options - Sanitization options
 * @returns {Object} - { sanitizedText, removedInvisible, stats }
 */
function sanitizeHtml(rawHtml, options = {}) {
  const {
    preserveLinks = false,
    maxLineLength = 0,
    wordwrap = false,
  } = options;

  const stats = {
    originalLength: rawHtml.length,
    invisibleBlocksRemoved: 0,
    hiddenCharsStripped: 0,
  };

  // Step 1: Remove invisible content
  let html = removeInvisibleContent(rawHtml);
  stats.invisibleBlocksRemoved = rawHtml.length - html.length;

  // Step 2: Convert HTML to plain text
  const textOptions = {
    wordwrap: wordwrap ? (maxLineLength || 80) : false,
    preserveNewlines: true,
    hideLinkHrefIfSameAsText: !preserveLinks,
    decodeEntities: true,
  };
  
  let text = convert(html, textOptions);

  // Step 3: Normalize Unicode
  text = normalizeUnicode(text);

  // Step 4: Strip hidden characters
  const beforeStrip = text.length;
  text = stripHiddenCharacters(text);
  stats.hiddenCharsStripped = beforeStrip - text.length;

  // Step 5: Collapse excessive whitespace
  text = text
    .replace(/\n{3,}/g, '\n\n') // Max 2 consecutive newlines
    .replace(/[ \t]+/g, ' ')      // Collapse horizontal whitespace
    .trim();

  return {
    sanitizedText: text,
    stats,
  };
}

/**
 * Sanitize a plain text email (already no HTML)
 * Still applies Unicode normalization and hidden character stripping
 */
function sanitizePlainText(rawText, options = {}) {
  let text = rawText;

  // Normalize Unicode
  text = normalizeUnicode(text);

  // Strip hidden characters
  text = stripHiddenCharacters(text);

  // Collapse whitespace
  text = text
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .trim();

  return {
    sanitizedText: text,
    stats: {
      originalLength: rawText.length,
      hiddenCharsStripped: rawText.length - text.length,
    },
  };
}

module.exports = {
  sanitizeHtml,
  sanitizePlainText,
  removeInvisibleContent,
  normalizeUnicode,
  stripHiddenCharacters,
  INVISIBLE_PATTERNS,
  ZERO_WIDTH_CHARS,
  RTL_OVERRIDES,
  HOMOGLYPH_MAP,
};