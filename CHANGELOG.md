# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-25

### Added
- **Canary Token System (v1.1)**
  - `src/canaryWord.js` — generate, inject, and check canary tokens
  - Inject unique random words into system prompts at strategic positions
  - Check LLM output for canary token leakage (exact and partial matches)
  - `createCanaryGuard()` — stateful guard with inject/check lifecycle
  - 50-word canary pool with hex suffix for uniqueness
  - Integrated into `EmailSecurityPipeline.processOutbound()` and `injectCanaryTokens()`

- **PII Anonymization (v1.2)**
  - `src/piiDetector.js` — detect emails, phones, names, addresses, Portuguese tax IDs (NIF/CC/NISS)
  - `src/piiAnonymizer.js` — replace PII with reversible placeholders, restore on output
  - Portuguese-specific patterns: NIF validation (mod-11), Portuguese addresses, formal name titles
  - Confidence levels (low/medium/high) and per-type detection toggles
  - Integrated into `processInbound()` (anonymize) and `processOutbound()` (deanonymize)
  - `piiMap` returned from inbound processing for outbound deanonymization

- **Encoding Attack Detection (v1.3)**
  - `src/encodingDetector.js` — decode and scan base64, ROT13, hex, quoted-printable, URL-encoded content
  - Decoded payloads checked against PatternMatcher for injection patterns
  - Heuristic validation to reduce false positives (printable ratio, length checks)
  - Long base64 strings flagged as suspicious even without injection content
  - Per-encoding-type toggles and custom pattern matcher support
  - Integrated into `processInbound()` before pattern matching

- **URL Safety Check (v1.4)**
  - `src/urlSafety.js` — flag suspicious URLs that may deliver prompt payloads
  - URL shortener detection (25+ domains: bit.ly, tinyurl, t.co, etc.)
  - Data URI detection (can embed arbitrary content/scripts)
  - IP-as-host detection (phishing indicator)
  - Punycode/IDN domain detection (homograph attacks)
  - Suspicious query parameter detection (prompt, inject, cmd, exec, etc.)
  - Excessive subdomain detection (obfuscation indicator)
  - Risk scoring (0–100) with clean/low/medium/high levels
  - Integrated into `processInbound()`

- **Adversarial Test Suite (v1.5)**
  - `test/adversarial/adversarial.test.js` — comprehensive red-team testing
  - Canary token leakage tests (exact, partial, obfuscated, multi-token)
  - PII bypass tests (Unicode obfuscation, Portuguese patterns, round-trip)
  - Encoding attack tests (base64, hex, ROT13, URL-encoded, QP, multi-encoding)
  - URL injection tests (shorteners, data URIs, IP hosts, punycode, multi-vector)
  - Combined multi-vector attack tests (HTML+PII+URL, base64+canary, etc.)
  - Stress test with mixed attack patterns

- **Pipeline Integration**
  - `processInbound()` now returns `piiMap`, `piiFound`, `encodingFlags`, `urlFlags`
  - `processOutbound()` now supports `checkCanaryLeak`, `deanonymizePII`, `piiMap` options
  - `injectCanaryTokens()` method for system prompt protection
  - `deanonymizePII()` method for restoring PII in outbound content
  - `getStatus()` includes canary, encoding, and URL safety status

- **New Tests**
  - `test/canaryWord.test.js` — 16 tests for canary token system
  - `test/pii.test.js` — 20 tests for PII detection and anonymization
  - `test/encodingDetector.test.js` — 16 tests for encoding attack detection
  - `test/urlSafety.test.js` — 18 tests for URL safety checking
  - `test/adversarial/adversarial.test.js` — 22 adversarial tests

### Changed
- `EmailSecurityPipeline` constructor accepts `canaryOptions`, `piiOptions`, `enableEncodingDetection`, `enableUrlSafety`
- `processInbound()` now runs encoding detection before pattern matching
- `processInbound()` now runs URL safety check after pattern matching
- `processInbound()` now anonymizes PII after all scanning is complete
- `processOutbound()` now checks for canary token leakage and deanonymizes PII
- Updated pipeline integration tests to cover v1.1-v1.4 features

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