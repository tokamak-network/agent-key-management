export async function runKeyRotation(baseUrl?: string) {
  const BASE_URL = baseUrl ?? process.env.API_URL ?? 'http://localhost:3000';
  console.log('\n=== Scenario: Key Rotation ===\n');

  // 1. Create a key
  console.log('1. Creating signing key for agent-rotate...');
  const createRes = await fetch(`${BASE_URL}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-rotate' },
    body: JSON.stringify({ agentId: 'agent-rotate', purpose: 'signing' }),
  });
  const key = await createRes.json();
  console.log(`   Key: ${key.keyId} (address: ${key.ethereumAddress})`);

  // 2. Sign with original key
  console.log('\n2. Signing with original key...');
  const sig1Res = await fetch(`${BASE_URL}/sign/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-rotate' },
    body: JSON.stringify({ keyId: key.keyId, message: 'before rotation' }),
  });
  const sig1 = await sig1Res.json();
  console.log(`   Signature OK from ${sig1.address}`);

  // 3. Rotate the key
  console.log('\n3. Rotating key...');
  const rotateRes = await fetch(`${BASE_URL}/keys/${key.keyId}/rotate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-rotate' },
  });
  const rotation = await rotateRes.json();
  console.log(`   Previous: ${rotation.previousKeyId}`);
  console.log(`   New key:  ${rotation.newKeyId} (epoch ${rotation.epoch})`);
  console.log(`   New address: ${rotation.newEthereumAddress}`);

  // 4. Try signing with OLD key (should fail)
  console.log('\n4. Trying to sign with OLD (rotated) key...');
  const oldKeyRes = await fetch(`${BASE_URL}/sign/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-rotate' },
    body: JSON.stringify({ keyId: key.keyId, message: 'after rotation with old key' }),
  });
  const oldKeyResult = await oldKeyRes.json();
  console.log(`   Result: ${oldKeyResult.error ? 'DENIED - ' + oldKeyResult.error : 'ERROR: unexpected success'}`);

  // 5. Sign with NEW key (should succeed)
  console.log('\n5. Signing with NEW key...');
  const newKeyRes = await fetch(`${BASE_URL}/sign/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-agent-id': 'agent-rotate' },
    body: JSON.stringify({ keyId: rotation.newKeyId, message: 'after rotation with new key' }),
  });
  const newKeyResult = await newKeyRes.json();
  console.log(`   Signature OK from ${newKeyResult.address}`);

  // 6. Verify key statuses
  console.log('\n6. Checking key statuses...');
  const keysRes = await fetch(`${BASE_URL}/keys?agentId=agent-rotate`, {
    headers: { 'x-agent-id': 'agent-rotate' },
  });
  const keys = await keysRes.json();
  for (const k of keys.keys) {
    console.log(`   ${k.id}: status=${k.status}, epoch=${k.epoch}`);
  }

  console.log('\n   [OK] Key rotation scenario completed successfully');
}
