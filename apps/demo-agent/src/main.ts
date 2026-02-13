import { serve } from '@hono/node-server';
import { createApp } from '@akm/api-server';
import { runBasicSigning } from './scenarios/basic-signing.js';
import { runPolicyEnforcement } from './scenarios/policy-enforcement.js';
import { runKeyRotation } from './scenarios/key-rotation.js';
import { runAttestationFlow } from './scenarios/attestation-flow.js';

async function waitForServer(url: string, retries = 20) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // Not ready yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Server did not start in time');
}

async function main() {
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║   TEE Agent Key Management - Demo Scenarios          ║');
  console.log('╚═══════════════════════════════════════════════════════╝');

  // Start embedded server
  const { app } = await createApp();
  const server = serve({ fetch: app.fetch, port: 0 });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 3000;
  process.env.API_URL = `http://localhost:${port}`;

  console.log(`\n[Demo] Embedded API server started on port ${port}`);

  // Wait for server to be ready
  await waitForServer(`http://localhost:${port}/health`);

  try {
    const url = `http://localhost:${port}`;
    await runBasicSigning(url);
    await runPolicyEnforcement(url);
    await runKeyRotation(url);
    await runAttestationFlow(url);

    console.log('\n╔═══════════════════════════════════════════════════════╗');
    console.log('║   All demo scenarios completed successfully!         ║');
    console.log('╚═══════════════════════════════════════════════════════╝\n');
  } catch (err) {
    console.error('\n[Demo] Scenario failed:', err);
    process.exitCode = 1;
  } finally {
    server.close();
  }
}

main();
