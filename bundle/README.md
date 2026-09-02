# Encrypted source bundle

`rose-mary-beauty.bundle.json` is the only application payload permitted in this public repository.
It is an authenticated `PFARMA_CI_BUNDLE_V2` envelope using AES-256-GCM.
The key exists only as the GitHub Actions secret `PFARMA_CI_BUNDLE_KEY` and must never be committed.
