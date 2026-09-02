# Rose&Mary Beauty — Public Encrypted CI Bridge

This repository is intentionally public and contains **no plaintext Rose&Mary Beauty application source, customer data, database credentials, API keys or runtime secrets**.

The application source is transported as one authenticated encrypted envelope using:

- format: `PFARMA_CI_BUNDLE_V2`
- algorithm: `AES-256-GCM`
- runtime key: GitHub Actions secret `PFARMA_CI_BUNDLE_KEY`

For reliable public transport, the encrypted envelope is split byte-for-byte into seven opaque files under `bundle/chunks/`. `bundle/manifest.json` pins the exact part count, byte length and SHA-256 of the reconstructed ciphertext. No individual chunk is executable or contains plaintext source.

GitHub Actions first validates the fail-closed public boundary and encrypted bundle integrity. Production jobs then reconstruct and decrypt the source only inside an ephemeral trusted runner, build it, deploy it to Cloudflare Workers and delete all decrypted/secret temporary material.

Production application data lives in Neon PostgreSQL under a least-privilege application role. This repository is only the encrypted public CI/deployment bridge.
