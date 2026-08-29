# Local container secrets

Only this README is tracked. Create and verify the first deployment inputs
without printing secret material:

```bash
python3 -B scripts/prepare_internal_sandbox_inputs.py create --output-root "$PWD/secrets"
python3 -B scripts/prepare_internal_sandbox_inputs.py verify --input-root "$PWD/secrets"
```

Then continue with `docs/operations/container-deployment.md`. The preparer owns
only:

- `db_superuser_password.txt` (at least 24 random bytes)
- `taxonomy_seed_workload_credential` (32..256 single-line ASCII bytes)
- `taxonomy_seed_receipt_hmac_key` (exactly 32 raw bytes)
- `oidc-client-secret` (32..4096 bytes, without NUL/newline)
- `internal-sandbox-identity-sources/` (the twenty exact fictional subject/email source files for ten accounts)

The separate TLS generator owns `internal-sandbox-tls/`. The later runtime-bundle
generator owns `internal-sandbox-bundle/` (three configs and exactly 36 generated
runtime secrets); the input preparer does not create either directory.

Any ignored bundle generated under an earlier secret contract must be rebuilt
into a new versioned directory. Do not delete or overwrite the old bundle
automatically; verify the new 36-secret bundle before switching the configured
bundle path. Historical `e2e-four-role-*` and `e2e-seven-account-*` trees remain
archives and must never be merged into or reused as the current ten-account input
root.

The old `session_hmac_key.txt` is not part of the production composition.
Never commit, print, upload, or copy these files into a container image.
