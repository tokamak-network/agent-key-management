export async function runPolicyEnforcement(baseUrl?: string) {
  const BASE_URL = baseUrl ?? process.env.API_URL ?? 'http://localhost:3000';
  console.log('\n=== Scenario: Policy Enforcement ===\n');

  // 1. Create a key
  console.log('1. Creating signing key for agent-policy...');
  const createRes = await fetch(`${BASE_URL}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-policy' },
    body: JSON.stringify({ agentId: 'agent-policy', purpose: 'signing' }),
  });
  const key = await createRes.json();
  console.log(`   Key created: ${key.keyId}`);

  // 2. Set spending limit policy
  console.log('\n2. Setting spending limit policy (max 0.5 ETH per tx, 1 ETH daily)...');
  const policyRes = await fetch(`${BASE_URL}/policy/${key.keyId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-policy' },
    body: JSON.stringify({
      rules: [
        {
          type: 'caller',
          allowedCallers: ['agent-policy'],
        },
        {
          type: 'spending-limit',
          maxValuePerTx: '500000000000000000',  // 0.5 ETH
          maxValuePerDay: '1000000000000000000', // 1 ETH
        },
        {
          type: 'allowlist',
          allowedAddresses: ['0x' + 'ab'.repeat(20)],
        },
      ],
    }),
  });
  const policyResult = await policyRes.json();
  console.log(`   Policy set with ${policyResult.rulesCount} rules`);

  // 3. Sign a small transaction (should succeed)
  console.log('\n3. Signing 0.1 ETH transaction (should succeed)...');
  const smallTxRes = await fetch(`${BASE_URL}/sign/transaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-policy' },
    body: JSON.stringify({
      keyId: key.keyId,
      transaction: {
        to: '0x' + 'ab'.repeat(20),
        value: '100000000000000000', // 0.1 ETH
        chainId: 1,
      },
    }),
  });
  const smallTx = await smallTxRes.json();
  console.log(`   Result: ${smallTx.hash ? 'SIGNED' : 'ERROR: ' + smallTx.error}`);

  // 4. Try to sign a large transaction (should be denied)
  console.log('\n4. Signing 2 ETH transaction (should be DENIED by spending limit)...');
  const largeTxRes = await fetch(`${BASE_URL}/sign/transaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-policy' },
    body: JSON.stringify({
      keyId: key.keyId,
      transaction: {
        to: '0x' + 'ab'.repeat(20),
        value: '2000000000000000000', // 2 ETH
        chainId: 1,
      },
    }),
  });
  const largeTx = await largeTxRes.json();
  console.log(`   Result: ${largeTx.error ? 'DENIED - ' + largeTx.error : 'ERROR: unexpected success'}`);

  // 5. Try unauthorized caller (should be denied)
  console.log('\n5. Signing with unauthorized caller (should be DENIED)...');
  const unauthorizedRes = await fetch(`${BASE_URL}/sign/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'hacker-agent' },
    body: JSON.stringify({
      keyId: key.keyId,
      message: 'trying to sign unauthorized',
    }),
  });
  const unauthorized = await unauthorizedRes.json();
  console.log(`   Result: ${unauthorized.error ? 'DENIED - ' + unauthorized.error : 'ERROR: unexpected success'}`);

  // 6. Try sending to non-allowlisted address (should be denied)
  console.log('\n6. Signing to non-allowlisted address (should be DENIED)...');
  const badAddrRes = await fetch(`${BASE_URL}/sign/transaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-policy' },
    body: JSON.stringify({
      keyId: key.keyId,
      transaction: {
        to: '0x' + 'de'.repeat(20),
        value: '100000000000000000',
        chainId: 1,
      },
    }),
  });
  const badAddr = await badAddrRes.json();
  console.log(`   Result: ${badAddr.error ? 'DENIED - ' + badAddr.error : 'ERROR: unexpected success'}`);

  console.log('\n   [OK] Policy enforcement scenario completed successfully');
}
