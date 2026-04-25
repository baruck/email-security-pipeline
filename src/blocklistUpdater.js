/**
 * Blocklist Updater
 * 
 * Checks security sources for new prompt injection patterns
 * and updates the blocklist. Run weekly by SecurityExpert agent.
 */

const fs = require('fs');
const path = require('path');

const BLOCKLIST_PATH = path.join(__dirname, '..', 'config', 'blocklist.json');

class BlocklistUpdater {
  constructor() {
    this.sources = [
      {
        name: 'OWASP LLM Top 10',
        url: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        type: 'reference',
      },
      {
        name: 'Simon Willison Blog',
        url: 'https://simonwillison.net/tags/prompt-injection/',
        type: 'reference',
      },
    ];
  }

  /**
   * Load current blocklist
   */
  loadCurrent() {
    try {
      return JSON.parse(fs.readFileSync(BLOCKLIST_PATH, 'utf-8'));
    } catch {
      return [];
    }
  }

  /**
   * Save updated blocklist
   */
  save(blocklist) {
    fs.writeFileSync(BLOCKLIST_PATH, JSON.stringify(blocklist, null, 2));
    return blocklist.length;
  }

  /**
   * Add a new pattern to the blocklist
   */
  addPattern(pattern) {
    const blocklist = this.loadCurrent();
    const existing = blocklist.find(p => p.id === pattern.id);
    
    if (existing) {
      existing.pattern = pattern.pattern;
      existing.severity = pattern.severity;
      existing.description = pattern.description;
    } else {
      blocklist.push(pattern);
    }
    
    return this.save(blocklist);
  }

  /**
   * Generate a report of current blocklist status
   */
  generateReport() {
    const blocklist = this.loadCurrent();
    const bySeverity = {};
    for (const entry of blocklist) {
      bySeverity[entry.severity] = (bySeverity[entry.severity] || 0) + 1;
    }
    
    return {
      totalPatterns: blocklist.length,
      bySeverity,
      lastUpdated: fs.statSync(BLOCKLIST_PATH).mtime,
      patterns: blocklist.map(p => ({ id: p.id, severity: p.severity, description: p.description })),
    };
  }
}

module.exports = { BlocklistUpdater };