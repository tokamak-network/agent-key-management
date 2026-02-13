export async function runAttestationFlow(baseUrl?: string) {
  const BASE_URL = baseUrl ?? process.env.API_URL ?? 'http://localhost:3000';
  console.log('\n=== Scenario: Attestation Flow ===\n');

  // 1. Request attestation quote
  console.log('1. Requesting attestation quote...');
  const quoteRes = await fetch(`${BASE_URL}/attestation/quote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce: 'verifier-challenge-' + Date.now() }),
  });
  const quote = await quoteRes.json();
  console.log(`   Provider: ${quote.report.provider}`);
  console.log(`   mrEnclave: ${quote.report.measurements.mrEnclave}`);
  console.log(`   mrSigner:  ${quote.report.measurements.mrSigner.slice(0, 32)}...`);
  console.log(`   Root PubKey: ${quote.rootPublicKey.slice(0, 32)}...`);
  console.log(`   Nonce: ${quote.nonce}`);

  // 2. Verify the quote
  console.log('\n2. Verifying attestation quote...');
  const verifyRes = await fetch(`${BASE_URL}/attestation/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quote }),
  });
  const verification = await verifyRes.json();
  console.log(`   Valid: ${verification.valid}`);

  // 3. Verify with expected measurements
  console.log('\n3. Verifying with expected mrEnclave...');
  const verifyExpectedRes = await fetch(`${BASE_URL}/attestation/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      quote,
      expectedMeasurements: { mrEnclave: quote.report.measurements.mrEnclave },
    }),
  });
  const verifyExpected = await verifyExpectedRes.json();
  console.log(`   Valid: ${verifyExpected.valid}`);

  // 4. Verify with WRONG expected measurement
  console.log('\n4. Verifying with WRONG expected mrEnclave (should fail)...');
  const verifyWrongRes = await fetch(`${BASE_URL}/attestation/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      quote,
      expectedMeasurements: { mrEnclave: 'wrong-measurement-hash' },
    }),
  });
  const verifyWrong = await verifyWrongRes.json();
  console.log(`   Valid: ${verifyWrong.valid}`);
  console.log(`   Reason: ${verifyWrong.reason}`);

  console.log('\n   [OK] Attestation flow scenario completed successfully');
}
