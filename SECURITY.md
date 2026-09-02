# Rose&Mary Beauty — public repository security boundary

This repository is intentionally public so GitHub Actions can provide the CI/deploy bridge without private-repository runner costs.

Never commit plaintext application source, `.env`/`.dev.vars`, customer data, database exports, credentials, tokens, private keys or decrypted workspaces.
The application exists publicly only as authenticated ciphertext in `bundle/rose-mary-beauty.bundle.json`.

Decryption is allowed only inside trusted GitHub Actions jobs on owner-controlled branches. The key is stored as the repository secret `PFARMA_CI_BUNDLE_KEY`.
Fork pull requests must never receive that secret. The production deployment workflow does not run on pull requests.
