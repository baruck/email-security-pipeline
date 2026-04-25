# Contributing to Email Security Pipeline

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/codunosor/email-security-pipeline.git
cd email-security-pipeline
npm install
npm test
```

## Making Changes

1. Fork the repo
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Commit with a clear message
6. Push to your fork
7. Open a Pull Request

## Adding Blocklist Patterns

Blocklist patterns live in `config/blocklist.json`. Each pattern has:

- `id` — unique identifier (kebab-case)
- `pattern` — JavaScript regex string (no delimiters)
- `severity` — `low`, `medium`, `high`, or `critical`
- `description` — human-readable explanation

When adding patterns:
- Test against both malicious and benign text to avoid false positives
- Prefer specificity over generality
- Include a comment in your PR explaining the attack vector the pattern covers

## Code Style

- Node.js (ES2020+)
- CommonJS modules (`require`/`module.exports`)
- 2-space indentation
- Descriptive variable names

## Reporting Security Vulnerabilities

Please **do not** report security vulnerabilities through public GitHub issues. Instead, [open a private security advisory on GitHub](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.