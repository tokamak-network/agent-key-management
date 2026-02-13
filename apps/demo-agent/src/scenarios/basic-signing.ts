export async function runBasicSigning(baseUrl?: string) {
  const BASE_URL = baseUrl ?? process.env.API_URL ?? 'http://localhost:3000';
  console.log('\n=== Scenario: Basic Signing ===\n');

  // 1. Create a key
  console.log('1. Creating signing key for agent-1...');
  const createRes = await fetch(`${BASE_URL}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-1' },
    body: JSON.stringify({ agentId: 'agent-1', purpose: 'signing' }),
  });
  const key = await createRes.json();
  console.log(`   Key created: ${key.keyId}`);
  console.log(`   Ethereum address: ${key.ethereumAddress}`);

  // 2. Sign a message
  console.log('\n2. Signing a message...');
  const signMsgRes = await fetch(`${BASE_URL}/sign/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-1' },
    body: JSON.stringify({
      keyId: key.keyId,
      message: 'Hello from TEE agent!',
    }),
  });
  const signedMsg = await signMsgRes.json();
  console.log(`   Signature: ${signedMsg.signature?.slice(0, 42)}...`);
  console.log(`   From address: ${signedMsg.address}`);

  // 3. Sign a transaction
  console.log('\n3. Signing an EVM transaction...');
  const signTxRes = await fetch(`${BASE_URL}/sign/transaction`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-1' },
    body: JSON.stringify({
      keyId: key.keyId,
      transaction: {
        to: '0x' + 'ab'.repeat(20),
        value: '1000000000000000000', // 1 ETH
        chainId: 1,
        maxFeePerGas: '20000000000',
        maxPriorityFeePerGas: '1000000000',
      },
    }),
  });
  const signedTx = await signTxRes.json();
  console.log(`   Signed TX hash: ${signedTx.hash}`);
  console.log(`   From: ${signedTx.from}`);

  console.log('\n   [OK] Basic signing scenario completed successfully');
  return { key, signedMsg, signedTx };
}
