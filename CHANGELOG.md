# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-25

### Added
- Layer 1: HTML → plain text sanitizer
  - Strip invisible HTML (display:none, opacity:0, font-size:0, etc.)
  - Remove script and style tags
  - Remove HTML comments (common injection hiding technique)
  - Normalize Unicode (NFKC) to catch homoglyphs and confusables
  - Strip zero-width characters, RTL overrides, BOM
  - Collapse excessive whitespace
- Layer 2: Pattern matching engine
  - 15 built-in prompt injection detection patterns
  - Severity levels: low, medium, high, critical
  - Configurable blocklist in JSON format
  - Hot-reloadable blocklist (no restart needed)
  - Custom pattern support at runtime
- Layer 3: Outbound review
  - Regex-based credential leak detection (API keys, passwords, tokens)
  - Infrastructure leak detection (private IPs, file paths, DB connection strings)
  - Configurable LLM-based review (OpenAI-compatible endpoints)
  - Heuristic over-compliance detection (for when no LLM is configured)
  - Quarantine workflow for flagged content
- Full pipeline orchestration
  - `processInbound()` — sanitize + scan incoming email
  - `processOutbound()` — review outgoing replies
  - Configurable quarantine handler
  - Pipeline status reporting
- Blocklist updater for recurring SecurityExpert monitoring
- 34 passing tests across all layers
- MIT License