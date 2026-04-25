# Email Security Pipeline

Sanitize, detect, and review emails before they reach any LLM — or leave any agent.

**Protect AI agents from prompt injection attacks delivered via email.**

## Why This Exists

AI agents that process email are vulnerable to **prompt injection attacks** embedded in:

- **Invisible HTML** — white-on-white text, `display:none`, `font-size:0`, `opacity:0`
- **Unicode tricks** — homoglyphs, zero-width characters, RTL overrides
- **Encoded payloads** — base64, quoted-printable, charset abuse
- **Social engineering** — disguised as legitimate replies to extract credentials or change agent behavior
- **Outbound leaks** — agents accidentally revealing API keys, passwords, internal IPs, or infrastructure details

This module processes every email through three defense layers **before** any LLM sees it, and reviews every outbound reply **before** it's sent.

## Architecture

```
Incoming Email → Layer 1 (Sanitize) → Layer 2 (Pattern Match) → Clean Text → LLM
Outbound Reply → Layer 3 (Review) → Approved / Quarantined → Send
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

// Process incoming email (Layers 1 + 2)
const result = pipeline.processInbound(rawEmailHtml, { isHtml: true });
if (result.safeForLLM) {
  // result.sanitizedText is clean — safe to feed to an LLM
  console.log(result.sanitizedText);
} else {
  // result.quarantined === true
  // result.flags tells you what was detected
  console.warn('Blocked:', result.flags);
}

// Review outgoing reply (Layer 3)
const review = await pipeline.processOutbound(replyText, originalEmail);
if (review.approved) {
  // Safe to send
  sendEmail(review.reply);
} else {
  // review.quarantined === true
  // review.flags tells you what leaked
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

### `pipeline.processInbound(content, options)`

Returns:
- `sanitizedText` — clean plain text
- `flags` — array of detected patterns
- `severity` — highest severity detected
- `quarantined` — whether content was flagged
- `safeForLLM` — `true` if content passed all checks

### `pipeline.processOutbound(reply, originalEmail, options)`

Returns:
- `approved` — whether the reply is safe to send
- `reply` — the reply text
- `flags` — any concerns detected
- `quarantined` — whether the reply needs human review

### `pipeline.reloadBlocklist(path?)`

Reload the blocklist from disk (use after SecurityExpert updates it).

### `pipeline.getStatus()`

Returns current pipeline configuration and blocklist summary.

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
npm test
```

34 tests covering all three layers plus full pipeline integration.

## Use Cases

- **AI email assistants** — protect agents that read and reply to email
- **Customer support bots** — prevent injection via support tickets
- **Email-to-task pipelines** — sanitize before processing
- **Multi-agent systems** — protect inter-agent email communication
- **Any workflow where untrusted email content reaches an LLM**

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions welcome — especially new blocklist patterns and attack vector research.

## License

MIT