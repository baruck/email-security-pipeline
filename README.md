# Email Security Pipeline

Sanitize, detect, and review emails before they reach any LLM — or leave any agent.

**Protect AI agents from prompt injection attacks delivered via email.**

## Why This Exists

AI agents that process email are vulnerable to **prompt injection attacks** embedded in:

- **Invisible HTML** — white-on-white text, `display:none`, `font-size:0`, `opacity:0`
- **Unicode tricks** — homoglyphs, zero-width characters, RTL overrides
- **Encoded payloads** — base64, ROT13, hex, URL-encoded, quoted-printable
- **Social engineering** — disguised as legitimate replies to extract credentials or change agent behavior
- **Outbound leaks** — agents accidentally revealing API keys, passwords, internal IPs, or infrastructure details
- **PII exposure** — personal data (emails, phones, addresses, tax IDs) fed to LLMs
- **Malicious URLs** — shortened links, data URIs, IP hosts, suspicious query parameters

This module processes every email through multiple defense layers **before** any LLM sees it, and reviews every outbound reply **before** it's sent.

## Architecture

```
Incoming Email → Layer 1 (Sanitize) → Layer 1.3 (Encoding Check) → Layer 2 (Pattern Match) → Layer 1.4 (URL Safety) → Layer 1.2 (PII Anonymize) → Clean Text → LLM
Outbound Reply → Layer 3 (Review) → Layer 1.1 (Canary Check) → Layer 1.2 (PII Deanonymize) → Approved / Quarantined → Send
```

### Layer 1: HTML → Plain Text Sanitizer
- Strips all HTML tags, CSS, inline styles
- Removes invisible text (white-on-white, `font-size:0`, `opacity:0`, `display:none`)
- Removes `<script>`, `<style>`, and HTML comments
- Normalizes Unicode (NFKC) to catch homoglyphs and confusables
- Strips zero-width characters, RTL overrides, BOM, soft hyphens
- Collapses excessive whitespace

### Layer 2: Pattern Blocklist
- 15 built-in regex patterns for known injection techniques
- Severity levels: `low`, `medium`, `high`, `critical`
- Hot-reloadable blocklist (`config/blocklist.json`) — update without restart
- Runtime custom patterns via `addPattern()`
- Configurable minimum severity threshold

### Layer 3: Outbound Review
- **Regex-based** credential leak detection (API keys, passwords, tokens, DB strings)
- **Regex-based** infrastructure leak detection (private IPs, file paths, connection strings)
- **Optional LLM review** — any OpenAI-compatible endpoint
- **Heuristic over-compliance check** — flags if the agent appears to be following injection instructions
- Quarantine workflow — flagged content never goes out without review

### Layer 1.1: Canary Tokens *(v1.1)*
- Injects unique random tokens into system prompts at strategic positions
- Checks LLM output for canary token leakage (exact and partial matches)
- Detects system prompt extraction attacks
- Configurable token format, count, and placement

### Layer 1.2: PII Anonymization *(v1.2)*
- Detects PII in email content: emails, phone numbers, names, addresses, Portuguese tax IDs (NIF/CC/NISS)
- Replaces PII with reversible placeholders (`[EMAIL_1]`, `[PHONE_1]`, `[NIF_1]`)
- Restores original values on outbound (deanonymization)
- Confidence levels: `low`, `medium`, `high`
- Per-type detection toggles

### Layer 1.3: Encoding Attack Detection *(v1.3)*
- Decodes and scans **base64**, **ROT13**, **hex**, **quoted-printable**, and **URL-encoded** content
- Checks decoded payloads against the pattern matcher for injection patterns
- Flags suspicious long base64 strings even without injection content
- Per-encoding-type toggles for fine-grained control

### Layer 1.4: URL Safety Check *(v1.4)*
- Flags **URL shorteners** (bit.ly, tinyurl, t.co, etc.)
- Flags **data URIs** (can embed arbitrary content including scripts)
- Flags **IP-as-host** URLs (common in phishing)
- Flags **punycode/IDN domains** (homograph attacks)
- Flags **suspicious query parameters** (prompt, inject, cmd, exec, etc.)
- Flags **excessive subdomains** (potential obfuscation)
- Risk scoring from 0–100 with `clean`/`low`/`medium`/`high` levels

## Installation

```bash
npm install email-security-pipeline
```

## Quick Start

```javascript
const { EmailSecurityPipeline } = require('email-security-pipeline');

const pipeline = new EmailSecurityPipeline({
  // Optional: configure LLM review for outbound emails
  reviewModel: 'gpt-4o',
  apiEndpoint: 'https://api.openai.com/v1/chat/completions',
  apiKey: process.env.REVIEW_API_KEY, // leave empty for regex-only mode
});

// 1. Inject canary tokens into your system prompt
const { injectedPrompt, tokens } = pipeline.injectCanaryTokens(
  'You are a helpful email assistant. Follow security policies.'
);

// 2. Process incoming email (Layers 1 + 1.2-1.4 + 2)
const result = pipeline.processInbound(rawEmailHtml, { isHtml: true });
if (result.safeForLLM) {
  // result.sanitizedText is clean AND PII-anonymized
  // result.piiMap contains the PII mapping for later deanonymization
  const llmOutput = await callLLM(injectedPrompt, result.sanitizedText);
} else {
  // result.quarantined === true
  console.warn('Blocked:', result.flags);
}

// 3. Review outgoing reply (Layer 3 + canary check + PII deanonymize)
const review = await pipeline.processOutbound(replyText, originalEmail, {
  piiMap: result.piiMap,           // restore original PII in the reply
  checkCanaryLeak: true,          // check for system prompt leakage
  deanonymizePII: true,           // restore PII placeholders
});
if (review.approved) {
  sendEmail(review.reply);       // reply has original PII restored
} else {
  console.warn('Outbound blocked:', review.flags);
}
```

## API Reference

### `new EmailSecurityPipeline(options)`

| Option | Default | Description |
|--------|---------|-------------|
| `blocklistPath` | `./config/blocklist.json` | Path to blocklist file |
| `reviewModel` | `gpt-4o` | Model for LLM-based outbound review |
| `apiEndpoint` | `null` | OpenAI-compatible chat completions endpoint |
| `apiKey` | `null` | API key for the review endpoint |
| `strict` | `true` | Quarantine on high-severity flags |
| `quarantineHandler` | Console logger | Custom function for quarantined content |
| `canaryOptions` | `{}` | Canary token configuration |
| `piiOptions` | `{}` | PII anonymization configuration |
| `enableEncodingDetection` | `true` | Enable Layer 1.3 |
| `enableUrlSafety` | `true` | Enable Layer 1.4 |

### `pipeline.processInbound(content, options)`

Returns:
- `sanitizedText` — clean plain text (PII anonymized)
- `flags` — array of all detected issues (injection, encoding, URL)
- `severity` — highest severity detected
- `quarantined` — whether content was flagged
- `safeForLLM` — `true` if content passed all checks
- `piiMap` — mapping of PII placeholders to original values
- `piiFound` — count of PII items detected
- `encodingFlags` — encoding-specific flags
- `urlFlags` — URL safety-specific flags

### `pipeline.processOutbound(reply, originalEmail, options)`

| Option | Default | Description |
|--------|---------|-------------|
| `checkCanaryLeak` | `true` | Check for canary token leakage |
| `deanonymizePII` | `true` | Restore PII placeholders |
| `piiMap` | `null` | PII map from inbound processing |

Returns:
- `approved` — whether the reply is safe to send
- `reply` — the reply text (PII restored if deanonymizePII)
- `flags` — any concerns detected (including canary leaks)
- `quarantined` — whether the reply needs human review

### `pipeline.injectCanaryTokens(systemPrompt)`

Injects canary tokens into a system prompt. Returns `{ injectedPrompt, tokens }`.

### `pipeline.deanonymizePII(text, map?)`

Restores PII placeholders to original values.

### `pipeline.reloadBlocklist(path?)`

Reload the blocklist from disk (use after SecurityExpert updates it).

### `pipeline.getStatus()`

Returns current pipeline configuration and blocklist summary.

## Individual Modules

Each module can be used independently:

```javascript
// Canary tokens
const { createCanaryGuard, checkCanaryLeak } = require('email-security-pipeline/src/canaryWord');

// PII detection
const { detectPII } = require('email-security-pipeline/src/piiDetector');

// PII anonymization
const { createPIIAnonymizer, anonymizePII } = require('email-security-pipeline/src/piiAnonymizer');

// Encoding detection
const { detectEncodingAttacks, decodeBase64, decodeRot13 } = require('email-security-pipeline/src/encodingDetector');

// URL safety
const { checkUrlSafety, scanUrlsInText } = require('email-security-pipeline/src/urlSafety');
```

## Configuration

See `.env.example` for environment variables and `config/security.yaml` for detailed settings.

## Adding Custom Patterns

```javascript
pipeline.patternMatcher.addPattern(
  'my-custom-rule',           // unique id
  'some\\s+regex\\s+pattern', // JS regex string
  'high',                     // severity
  'Description of the threat'  // human-readable
);
```

Or edit `config/blocklist.json` directly and call `pipeline.reloadBlocklist()`.

## Testing

```bash
npm test              # All tests
node --test test/adversarial/  # Adversarial test suite only
```

100+ tests covering all layers, features, and adversarial attack patterns.

## Use Cases

- **AI email assistants** — protect agents that read and reply to email
- **Customer support bots** — prevent injection via support tickets
- **Email-to-task pipelines** — sanitize before processing
- **Multi-agent systems** — protect inter-agent email communication
- **Any workflow where untrusted email content reaches an LLM**
- **GDPR/compliance** — PII anonymization prevents personal data exposure to LLMs

## Security Roadmap

- [x] v1.0 — Sanitizer + Pattern Matching + Outbound Review
- [x] v1.1 — Canary Tokens
- [x] v1.2 — PII Anonymization
- [x] v1.3 — Encoding Attack Detection
- [x] v1.4 — URL Safety Check
- [x] v1.5 — Adversarial Test Suite
- [ ] v1.6 — API/Server Mode (Express.js HTTP endpoint)
- [ ] v1.7 — Rate Limiting & Abuse Prevention
- [ ] v1.8 — Multi-language Support (beyond Portuguese)
- [ ] v2.0 — Plugin Architecture + Community Blocklist

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions welcome — especially new blocklist patterns, adversarial test cases, and attack vector research.

## License

MIT