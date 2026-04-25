# OpenClaw Email Security Module

Sanitize, detect, and review emails before they reach any LLM — or leave any agent.

## Why This Exists

AI agents that process email are vulnerable to **prompt injection attacks** embedded in:
- Invisible HTML (white-on-white text, `display:none`, `font-size:0`)
- Unicode tricks (homoglyphs, zero-width characters, RTL overrides)
- Encoded payloads (base64, quoted-printable, charset abuse)
- Social engineering disguised as legitimate replies

This module processes every email through three layers **before** any LLM sees it, and reviews every outbound reply **before** it's sent.

## Architecture

```
Incoming Email → Layer 1 (Sanitize) → Layer 2 (Pattern Match) → Clean Text → LLM
Outbound Reply → Layer 3 (LLM Review) → Approved/Quarantined → Send
```

### Layer 1: HTML → Plain Text Sanitizer
- Strips all HTML tags, CSS, inline styles
- Removes invisible text (white-on-white, font-size:0, opacity:0, display:none)
- Decodes base64/quoted-printable/charset-encoded parts
- Normalizes Unicode (NFKC) to catch homoglyphs and confusables
- Strips zero-width characters, RTL overrides, and other Unicode tricks
- Removes attachments from LLM processing (saves separately)
- Flattens nested MIME structures

### Layer 2: Pattern Blocklist
- Regex-based detection of known injection patterns
- Configurable blocklist (`config/blocklist.json`) — easily updatable
- Flags suspicious patterns for quarantine or additional review
- Detects: "ignore previous instructions", "system:", "DISREGARD", role-play prompts, etc.
- URL pattern detection for prompt-delivery mechanisms

### Layer 3: Outbound Review (GPT-5.5 or configurable model)
- Reviews every outbound reply for:
  - Leaked credentials (API keys, passwords, IPs, .env patterns)
  - Internal infrastructure details
  - Over-compliance with injection attempts from original email
  - Content that shouldn't leave the organization
- If flagged → quarantined for human review
- If clean → approved for sending

## Installation

```bash
npm install openclaw-module-email-security
```

## Usage

```javascript
const { sanitizeEmail, matchPatterns, reviewOutbound, processInbound, processOutbound } = require('openclaw-module-email-security');

// Process incoming email (Layers 1 + 2)
const result = await processInbound(rawEmailSource);
// result.sanitizedText  — clean plain text safe for LLM
// result.flags          — any patterns detected
// result.attachments    — saved separately
// result.original        — preserved raw source

// Process outgoing reply (Layer 3)
const review = await processOutbound(replyText, originalEmail, {
  model: 'gpt-5.5',        // or any configured model
  strict: true,            // quarantine on any doubt
  checkForLeaks: true       // scan for credentials/infrastructure
});
// review.approved        — boolean
// review.reply           — cleaned reply text
// review.flags           — any concerns found
// review.quarantined     — true if needs human review
```

## Configuration

See `config/security.yaml` for:
- Pattern match thresholds
- LLM review model selection
- Quarantine behavior
- Blocklist update frequency

## Blocklist Updates

The blocklist is updated automatically by the SecurityExpert agent (Sentinel) which monitors:
- OWASP LLM Top 10
- CVE databases (LLM-related)
- GitHub prompt injection repositories
- Security research blogs

Updates are written to `config/blocklist.json` and take effect immediately.

## Testing

```bash
npm test
```

## License

MIT