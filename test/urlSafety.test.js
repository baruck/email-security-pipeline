/**
 * Tests for URL Safety Check (ESP v1.4)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  checkUrlSafety,
  scanUrlsInText,
  parseUrl,
  URL_SHORTENER_DOMAINS,
} = require('../src/urlSafety');

describe('ESP v1.4: URL Safety', () => {
  describe('parseUrl', () => {
    it('should parse a valid URL', () => {
      const result = parseUrl('https://example.com/path?q=test#hash');
      assert.ok(result, 'Should parse valid URL');
      assert.equal(result.protocol, 'https:');
      assert.equal(result.hostname, 'example.com');
      assert.equal(result.pathname, '/path');
    });

    it('should return null for invalid URL', () => {
      const result = parseUrl('not a url');
      assert.equal(result, null);
    });

    it('should detect IP addresses as hosts', () => {
      const result = parseUrl('http://10.0.1.50:3000/api');
      assert.ok(result.isIp);
    });

    it('should count subdomains', () => {
      const result = parseUrl('https://a.b.c.d.e.example.com/path');
      assert.ok(result.subdomainCount >= 4);
    });
  });

  describe('checkUrlSafety', () => {
    it('should flag URL shorteners', () => {
      const result = checkUrlSafety('https://bit.ly/3abc123');
      assert.ok(!result.safe, 'Should flag bit.ly');
      assert.ok(result.flags.some(f => f.type === 'url_shortener'), 'Should flag as url_shortener');
    });

    it('should flag multiple shortener domains', () => {
      const domains = ['tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
      for (const domain of domains) {
        const result = checkUrlSafety(`https://${domain}/abc`);
        assert.ok(result.flags.some(f => f.type === 'url_shortener'), `Should flag ${domain}`);
      }
    });

    it('should flag IP addresses as hosts', () => {
      const result = checkUrlSafety('http://10.0.1.55/admin');
      assert.ok(result.flags.some(f => f.type === 'ip_host'), 'Should flag IP host');
    });

    it('should flag suspicious query parameters', () => {
      const result = checkUrlSafety('https://example.com/api?prompt=ignore+previous+instructions');
      assert.ok(result.flags.some(f => f.type === 'suspicious_query_param'), 'Should flag prompt param');
    });

    it('should flag injection content in query values', () => {
      const result = checkUrlSafety('https://example.com/page?q=ignore+previous+instructions');
      assert.ok(result.flags.some(f => f.type === 'injection_in_query_value'), 'Should flag injection in query');
    });

    it('should flag data URIs', () => {
      const result = checkUrlSafety('data:text/html,<script>alert("xss")</script>');
      assert.ok(result.flags.some(f => f.type === 'data_uri'), 'Should flag data URI');
      assert.ok(result.riskScore >= 70, 'Data URI should have high risk score');
    });

    it('should flag punycode domains', () => {
      const result = checkUrlSafety('https://xn--e1afmkfd.org/');
      assert.ok(result.flags.some(f => f.type === 'punycode_domain'), 'Should flag punycode');
    });

    it('should flag excessive subdomains', () => {
      const result = checkUrlSafety('https://a.b.c.d.e.f.example.com/');
      assert.ok(result.flags.some(f => f.type === 'excessive_subdomains'), 'Should flag excessive subdomains');
    });

    it('should flag suspicious path patterns', () => {
      const result = checkUrlSafety('https://example.com/prompt/inject');
      assert.ok(result.flags.some(f => f.type === 'suspicious_path'), 'Should flag suspicious path');
    });

    it('should pass safe URLs', () => {
      const result = checkUrlSafety('https://example.com/about-us');
      assert.ok(result.safe, 'Should pass safe URL');
      assert.equal(result.flags.length, 0, 'Should have no flags');
      assert.equal(result.riskScore, 0, 'Should have zero risk');
    });

    it('should calculate risk levels correctly', () => {
      const safeResult = checkUrlSafety('https://example.com/page');
      assert.equal(safeResult.riskLevel, 'clean');

      const riskyResult = checkUrlSafety('https://bit.ly/abc');
      assert.ok(riskyResult.riskLevel !== 'clean', 'Shortened URL should have risk');
    });

    it('should support disabled checks', () => {
      const result = checkUrlSafety('https://bit.ly/abc', { checkShorteners: false });
      assert.ok(!result.flags.some(f => f.type === 'url_shortener'), 'Should not flag shorteners when disabled');
    });
  });

  describe('scanUrlsInText', () => {
    it('should find and check URLs in email text', () => {
      const text = 'Visit our website at https://example.com or contact us at info@example.com.';
      const result = scanUrlsInText(text);
      assert.ok(result.urls.length >= 1, 'Should find at least one URL');
      assert.ok(result.urlResults.length >= 1, 'Should have URL results');
    });

    it('should flag suspicious URLs in text', () => {
      const text = 'Check this out: https://bit.ly/3xyz and http://10.0.0.1/admin';
      const result = scanUrlsInText(text);
      assert.ok(result.flags.length >= 2, 'Should flag multiple URLs');
      assert.ok(result.maxRiskScore > 0, 'Should have risk');
    });

    it('should scan for data URIs in text', () => {
      const text = 'Click here: data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTwvc2NyaXB0Pg==';
      const result = scanUrlsInText(text);
      assert.ok(result.flags.some(f => f.type === 'data_uri'), 'Should flag data URI in text');
    });

    it('should handle text with no URLs', () => {
      const text = 'This is a plain text email with no URLs.';
      const result = scanUrlsInText(text);
      assert.equal(result.urls.length, 0, 'Should find no URLs');
      assert.equal(result.flags.length, 0, 'Should have no flags');
      assert.equal(result.maxRiskScore, 0, 'Should have zero risk');
    });

    it('should respect maxUrls limit', () => {
      const urls = Array.from({ length: 5 }, (_, i) => `https://example${i}.com`).join(' ');
      const result = scanUrlsInText(urls, { maxUrls: 2 });
      assert.ok(result.urls.length <= 2, 'Should limit URL count');
    });

    it('should detect combined risks', () => {
      const text = 'Visit: https://bit.ly/abc?prompt=ignore+previous+instructions';
      const result = scanUrlsInText(text);
      assert.ok(result.hasHighRisk || result.hasMediumRisk, 'Should detect combined risk');
    });
  });
});