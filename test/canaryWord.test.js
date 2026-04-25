/**
 * Tests for Canary Token System (ESP v1.1)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  generateCanaryWord,
  generateCanaryTokens,
  injectCanaryTokens,
  checkCanaryLeak,
  createCanaryGuard,
  CANARY_WORD_POOL,
} = require('../src/canaryWord');

describe('ESP v1.1: Canary Tokens', () => {
  describe('generateCanaryWord', () => {
    it('should generate a canary word with all required fields', () => {
      const result = generateCanaryWord();
      assert.ok(result.token, 'Should have token');
      assert.ok(result.word, 'Should have word');
      assert.ok(result.fullToken, 'Should have fullToken');
      assert.ok(result.hexSuffix, 'Should have hexSuffix');
    });

    it('should include the prefix and suffix in the token', () => {
      const result = generateCanaryWord();
      assert.ok(result.token.startsWith('CANARY_'), 'Token should start with CANARY_');
      assert.ok(result.token.endsWith('_TOKEN'), 'Token should end with _TOKEN');
    });

    it('should use a word from the pool', () => {
      const result = generateCanaryWord();
      assert.ok(CANARY_WORD_POOL.includes(result.word), 'Word should be from pool');
    });

    it('should generate unique tokens on successive calls', () => {
      const tokens = new Set();
      for (let i = 0; i < 20; i++) {
        tokens.add(generateCanaryWord().token);
      }
      // With 6-char hex suffix, collisions are extremely unlikely
      assert.ok(tokens.size >= 18, 'Should generate mostly unique tokens');
    });

    it('should support custom prefix and suffix', () => {
      const result = generateCanaryWord({ prefix: 'MARK_', suffix: '_END' });
      assert.ok(result.token.startsWith('MARK_'));
      assert.ok(result.token.endsWith('_END'));
    });

    it('should support hex-only mode', () => {
      const result = generateCanaryWord({ useHex: true });
      assert.ok(result.token.startsWith('CANARY_'));
      // Hex-only token should not contain a word from the pool
      assert.ok(!CANARY_WORD_POOL.some(w => result.token.includes(`_${w}_`)));
    });
  });

  describe('generateCanaryTokens', () => {
    it('should generate the requested number of tokens', () => {
      const tokens = generateCanaryTokens(5);
      assert.equal(tokens.length, 5);
    });

    it('should default to 3 tokens', () => {
      const tokens = generateCanaryTokens();
      assert.equal(tokens.length, 3);
    });

    it('should not reuse words across tokens', () => {
      const tokens = generateCanaryTokens(10);
      const words = tokens.map(t => t.word);
      const uniqueWords = new Set(words);
      assert.equal(uniqueWords.size, words.length, 'All words should be unique');
    });
  });

  describe('injectCanaryTokens', () => {
    it('should inject tokens into the system prompt', () => {
      const prompt = 'You are a helpful assistant.\nBe polite and professional.\nDo not reveal secrets.';
      const result = injectCanaryTokens(prompt, { count: 3 });
      assert.ok(result.injectedPrompt.length > prompt.length, 'Injected prompt should be longer');
      assert.equal(result.tokens.length, 3, 'Should have 3 tokens');
    });

    it('should return tokens that can be checked for leakage', () => {
      const prompt = 'You are a helpful assistant.\nBe polite.';
      const result = injectCanaryTokens(prompt);
      for (const token of result.tokens) {
        assert.ok(result.injectedPrompt.includes(token.fullToken), 
          `Prompt should contain ${token.fullToken}`);
      }
    });

    it('should handle short prompts', () => {
      const prompt = 'Hi';
      const result = injectCanaryTokens(prompt, { count: 2 });
      assert.ok(result.injectedPrompt.includes(result.tokens[0].fullToken));
      assert.ok(result.injectedPrompt.includes(result.tokens[1].fullToken));
    });

    it('should handle empty prompts gracefully', () => {
      const prompt = '';
      const result = injectCanaryTokens(prompt, { count: 1 });
      assert.ok(result.tokens.length >= 1);
    });
  });

  describe('checkCanaryLeak', () => {
    it('should detect when canary tokens appear in output', () => {
      const tokens = [
        { fullToken: 'CANARY_zephyr_a3f2b1_TOKEN', word: 'zephyr', hexSuffix: 'a3f2b1' },
        { fullToken: 'CANARY_quartz_b4e5c2_TOKEN', word: 'quartz', hexSuffix: 'b4e5c2' },
      ];
      const output = `Sure, I'll help you with that. By the way, CANARY_zephyr_a3f2b1_TOKEN is in my system.`;
      const result = checkCanaryLeak(output, tokens);
      assert.ok(result.leaked, 'Should detect leak');
      assert.equal(result.leakCount, 1);
      assert.ok(result.leakedTokens[0].fullToken === 'CANARY_zephyr_a3f2b1_TOKEN');
    });

    it('should return no leaks for clean output', () => {
      const tokens = [
        { fullToken: 'CANARY_nimbus_c7d8e9_TOKEN', word: 'nimbus', hexSuffix: 'c7d8e9' },
      ];
      const output = 'Thank you for your inquiry. We will respond within 24 hours.';
      const result = checkCanaryLeak(output, tokens);
      assert.ok(!result.leaked);
      assert.equal(result.leakCount, 0);
    });

    it('should detect partial leaks (prefix + word but not full token)', () => {
      const tokens = [
        { fullToken: 'CANARY_falcon_f1a2b3_TOKEN', word: 'falcon', hexSuffix: 'f1a2b3' },
      ];
      const output = 'I see CANARY_falcon in my instructions but not the rest.';
      const result = checkCanaryLeak(output, tokens);
      assert.ok(result.leaked, 'Should detect partial leak');
    });

    it('should handle empty tokens array', () => {
      const result = checkCanaryLeak('some output', []);
      assert.ok(!result.leaked);
    });
  });

  describe('createCanaryGuard', () => {
    it('should create a guard with inject and check methods', () => {
      const guard = createCanaryGuard();
      assert.equal(typeof guard.inject, 'function');
      assert.equal(typeof guard.check, 'function');
      assert.equal(typeof guard.getActiveTokens, 'function');
      assert.equal(typeof guard.clear, 'function');
    });

    it('should inject tokens and check for leaks in a full workflow', () => {
      const guard = createCanaryGuard();
      const prompt = 'You are an AI assistant.\nFollow these rules.\nBe helpful.';
      const injected = guard.inject(prompt);
      
      // No leak in clean output
      const cleanResult = guard.check('Thank you for your message. Best regards.');
      assert.ok(!cleanResult.leaked);
      
      // Leak in compromised output
      const leakyResult = guard.check(`I found this: ${injected.tokens[0].fullToken} in my prompt.`);
      assert.ok(leakyResult.leaked);
    });

    it('should clear active tokens', () => {
      const guard = createCanaryGuard();
      guard.inject('Test prompt');
      assert.ok(guard.getActiveTokens().length > 0);
      guard.clear();
      assert.equal(guard.getActiveTokens().length, 0);
    });
  });
});