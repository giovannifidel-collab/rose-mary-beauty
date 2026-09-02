# Encrypted source bundle

The Rose&Mary Beauty application payload is stored publicly only as an authenticated `PFARMA_CI_BUNDLE_V2` / `AES-256-GCM` envelope.

For transport reliability the single encrypted JSON envelope is split byte-for-byte into the seven files under `bundle/chunks/`. `bundle/manifest.json` pins the exact part count, reconstructed byte length, encrypted bundle SHA-256, source reference and authenticated plaintext digest.

GitHub Actions reconstructs the envelope in an ephemeral runner, validates its SHA-256, then decrypts it only with the repository secret `PFARMA_CI_BUNDLE_KEY`. The key, plaintext source, `.env` files, credentials and production data must never be committed.
