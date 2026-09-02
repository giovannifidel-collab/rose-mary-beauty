# Rose&Mary Beauty — Public Encrypted CI Bridge

This repository is intentionally public and contains **no plaintext Rose&Mary Beauty application source, customer data, database credentials, API keys or runtime secrets**.

The application source is stored as an authenticated encrypted bundle using:

- format: `PFARMA_CI_BUNDLE_V2`
- algorithm: `AES-256-GCM`
- runtime key: GitHub Actions secret `PFARMA_CI_BUNDLE_KEY`

GitHub Actions validates the public boundary, decrypts the source only inside the trusted runner, builds/tests it, deploys to Cloudflare Workers, then removes the decrypted workspace.

Production state lives in Neon PostgreSQL; this repository is only the public CI/deployment bridge.
