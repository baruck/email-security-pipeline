/**
 * Layer 2: Pattern Matching Engine
 * 
 * Loads blocklist patterns and scans sanitized text for known injection patterns.
 * Returns flagged content with severity levels.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_BLOCKLIST_PATH = path.join(__dirname, '..', 'config', 'blocklist.json');

class PatternMatcher {
  constructor(blocklistPath = DEFAULT_BLOCKLIST_PATH) {
    this.blocklist = this.loadBlocklist(blocklistPath);
    this.compiledPatterns = this.compilePatterns(this.blocklist);
  }

  /**
   * Load blocklist from JSON file
   */
  loadBlocklist(filePath) {
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(raw);
    } catch (err) {
      console.warn(`Failed to load blocklist from ${filePath}: ${err.message}`);
      return [];
    }
  }

  /**
   * Reload blocklist (for when SecurityExpert updates it)
   */
  reload(blocklistPath) {
    this.blocklist = this.loadBlocklist(blocklistPath || DEFAULT_BLOCKLIST_PATH);
    this.compiledPatterns = this.compilePatterns(this.blocklist);
    return this.blocklist.length;
  }

  /**
   * Compile regex patterns from blocklist entries
   */
  compilePatterns(blocklist) {
    return blocklist.map(entry => ({
      ...entry,
      compiledRegex: new RegExp(entry.pattern, 'gi'),
    }));
  }

  /**
   * Scan text for injection patterns
   * @param {string} text - Sanitized plain text to scan
   * @param {Object} options - Scanning options
   * @returns {Object} - { clean, flags, severity, requiresReview }
   */
  scan(text, options = {}) {
    const {
      minSeverity = 'low',      // Minimum severity to flag (low, medium, high, critical)
      maxFlags = 50,             // Maximum flags to return
      quarantineOnCritical = true, // Quarantine on any critical match
    } = options;

    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const minIndex = severityOrder.indexOf(minSeverity);

    const flags = [];
    let maxSeverity = 'clean';

    for (const pattern of this.compiledPatterns) {
      const severityIndex = severityOrder.indexOf(pattern.severity);
      if (severityIndex < minIndex) continue;

      // Reset regex lastIndex for global patterns
      pattern.compiledRegex.lastIndex = 0;
      const matches = text.match(pattern.compiledRegex);

      if (matches) {
        flags.push({
          id: pattern.id,
          description: pattern.description,
          severity: pattern.severity,
          matches: matches.length,
          sample: matches[0].substring(0, 100),
        });

        // Track highest severity
        if (severityIndex > severityOrder.indexOf(maxSeverity)) {
          maxSeverity = pattern.severity;
        }
      }

      if (flags.length >= maxFlags) break;
    }

    const isClean = flags.length === 0;
    const requiresReview = !isClean && (
      quarantineOnCritical && maxSeverity === 'critical' ||
      maxSeverity === 'high'
    );

    return {
      clean: isClean,
      flags,
      severity: maxSeverity,
      requiresReview,
      flagCount: flags.length,
    };
  }

  /**
   * Add a custom pattern to the blocklist (runtime only, not persisted)
   */
  addPattern(id, pattern, severity, description) {
    const entry = {
      id,
      pattern,
      severity,
      description,
      compiledRegex: new RegExp(pattern, 'gi'),
    };
    this.blocklist.push(entry);
    this.compiledPatterns.push(entry);
    return entry;
  }

  /**
   * Get summary of loaded patterns
   */
  getSummary() {
    const bySeverity = {};
    for (const entry of this.blocklist) {
      bySeverity[entry.severity] = (bySeverity[entry.severity] || 0) + 1;
    }
    return {
      totalPatterns: this.blocklist.length,
      bySeverity,
      lastUpdated: fs.statSync(DEFAULT_BLOCKLIST_PATH).mtime,
    };
  }
}

module.exports = { PatternMatcher };