import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createApp } from '@akm/api-server';
import type { Hono } from 'hono';

describe('API E2E', () => {
  let app: Hono<any>;

  beforeAll(async () => {
    const result = await createApp();
    app = result.app;
  });

  async function request(method: string, path: string, body?: any, headers?: Record<string, string>) {
    const init: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    };
    if (body) init.body = JSON.stringify(body);

    const url = `http://localhost${path}`;
    return app.request(url, init);
  }

  describe('Health', () => {
    it('GET /health should return ok', async () => {
      const res = await request('GET', '/health');
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('ok');
      expect(data.teeProvider).toBe('simulator');
    });
  });

  describe('Keys', () => {
    it('POST /keys should create a key', async () => {
      const res = await request('POST', '/keys', { agentId: 'test-agent', purpose: 'signing' }, { 'x-agent-id': 'test-agent' });
      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.keyId).toBe('test-agent/signing/epoch-0');
      expect(data.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
      expect(data.publicKey).toMatch(/^04[0-9a-f]{128}$/);
    });

    it('GET /keys should list keys', async () => {
      const res = await request('GET', '/keys', undefined, { 'x-agent-id': 'test-agent' });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.keys.length).toBeGreaterThan(0);
    });

    it('GET /keys should require auth', async () => {
      const res = await request('GET', '/keys');
      expect(res.status).toBe(401);
    });

    it('POST /keys/:id/rotate should rotate a key', async () => {
      // Create first
      await request('POST', '/keys', { agentId: 'rotate-test', purpose: 'signing' }, { 'x-agent-id': 'rotate-test' });

      const res = await request('POST', '/keys/rotate-test/signing/epoch-0/rotate', undefined, { 'x-agent-id': 'rotate-test' });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.epoch).toBe(1);
      expect(data.previousKeyId).toBe('rotate-test/signing/epoch-0');
    });
  });

  describe('Signing', () => {
    let keyId: string;

    beforeAll(async () => {
      const res = await request('POST', '/keys', { agentId: 'signer', purpose: 'signing' }, { 'x-agent-id': 'signer' });
      const data = await res.json();
      keyId = data.keyId;
    });

    it('POST /sign/message should sign a message', async () => {
      const res = await request('POST', '/sign/message', {
        keyId,
        message: 'test message',
      }, { 'x-agent-id': 'signer' });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.signature).toMatch(/^0x[0-9a-f]+$/);
      expect(data.address).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it('POST /sign/transaction should sign a transaction', async () => {
      const res = await request('POST', '/sign/transaction', {
        keyId,
        transaction: {
          to: '0x' + 'ab'.repeat(20),
          value: '1000000000000000000',
          chainId: 1,
        },
      }, { 'x-agent-id': 'signer' });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.signedTransaction).toBeTruthy();
      expect(data.hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it('should not include private key in any response', async () => {
      // Create key
      const createRes = await request('POST', '/keys', { agentId: 'security-test', purpose: 'signing' }, { 'x-agent-id': 'security-test' });
      const createData = await createRes.json();

      // Get key metadata
      const getRes = await request('GET', `/keys/${createData.keyId}`, undefined, { 'x-agent-id': 'security-test' });
      const getData = await getRes.json();

      // Sign message
      const signRes = await request('POST', '/sign/message', {
        keyId: createData.keyId,
        message: 'check security',
      }, { 'x-agent-id': 'security-test' });
      const signData = await signRes.json();

      // Verify none of the responses contain private key material
      const allResponses = JSON.stringify([createData, getData, signData]);
      expect(allResponses).not.toContain('privateKey');
      expect(allResponses).not.toContain('private_key');
      expect(allResponses).not.toContain('secret');
    });
  });

  describe('Policy', () => {
    let keyId: string;

    beforeAll(async () => {
      const res = await request('POST', '/keys', { agentId: 'policy-agent', purpose: 'signing' }, { 'x-agent-id': 'policy-agent' });
      const data = await res.json();
      keyId = data.keyId;
    });

    it('PUT /policy/:keyId should set policy', async () => {
      const res = await request('PUT', `/policy/${keyId}`, {
        rules: [
          { type: 'caller', allowedCallers: ['policy-agent'] },
          { type: 'spending-limit', maxValuePerTx: '1000000000000000000', maxValuePerDay: '5000000000000000000' },
        ],
      }, { 'x-agent-id': 'policy-agent' });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.rulesCount).toBe(2);
    });

    it('should deny unauthorized callers after policy is set', async () => {
      const res = await request('POST', '/sign/message', {
        keyId,
        message: 'hack attempt',
      }, { 'x-agent-id': 'hacker' });

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toContain('Policy denied');
    });

    it('should allow authorized callers', async () => {
      const res = await request('POST', '/sign/message', {
        keyId,
        message: 'authorized request',
      }, { 'x-agent-id': 'policy-agent' });

      expect(res.status).toBe(200);
    });
  });

  describe('Attestation', () => {
    it('POST /attestation/quote should generate a quote', async () => {
      const res = await request('POST', '/attestation/quote', { nonce: 'test-nonce-123' });
      expect(res.status).toBe(200);

      const quote = await res.json();
      expect(quote.report.provider).toBe('simulator');
      expect(quote.nonce).toBe('test-nonce-123');
      expect(quote.rootPublicKey).toBeTruthy();
    });

    it('POST /attestation/verify should verify a valid quote', async () => {
      // Generate
      const genRes = await request('POST', '/attestation/quote', { nonce: 'verify-nonce' });
      const quote = await genRes.json();

      // Verify
      const verRes = await request('POST', '/attestation/verify', { quote });
      const result = await verRes.json();
      expect(result.valid).toBe(true);
    });

    it('POST /attestation/verify should reject tampered quote', async () => {
      const genRes = await request('POST', '/attestation/quote', { nonce: 'tamper-nonce' });
      const quote = await genRes.json();

      // Tamper
      quote.nonce = 'tampered';

      const verRes = await request('POST', '/attestation/verify', { quote });
      const result = await verRes.json();
      expect(result.valid).toBe(false);
    });
  });
});
