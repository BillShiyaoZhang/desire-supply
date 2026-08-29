# PostgreSQL OIDC production bundle

Status: G1 internal-pilot implementation contract, 2026-08-12.

This slice strengthens the existing IAM User and Session model. It does not
create a second account store, a local password path, or a client-held
business Session.

## Open capability

The first production PostgreSQL slice supports exactly one flow:

1. an anonymous browser begins `LOGIN`;
2. OIDC Authorization Code + PKCE is completed by a configured real provider;
3. the verified `(issuer, subject digest, subject key ID)` resolves one existing
   ACTIVE external identity whose User is ACTIVE;
4. one new server-side Session family and Session are committed atomically.

Invitation `ENROLLMENT`, invitation `STEP_UP`, and current-Session rotation
remain closed with `SERVICE_UNAVAILABLE`. They must not fall back to a local
password, a synthetic provider, or automatic User creation.

## Composition contract

The server composition root constructs one
`PsycopgOidcAuthenticationUnitOfWork` from an `iam_onboarding` connection
source, then calls:

```python
build_postgres_iam_authentication_bundle(
    oidc_uow=oidc_uow,
    provider=closed_oidc_provider,
    protocol_keyring=protocol_keyring,
    protocol_secret_box=protocol_secret_box,
    session_keyring=session_keyring,
    clock=clock,
    id_source=id_source,
    secret_source=secret_source,
    system_actor_id=system_actor_id,
    security_policy=security_policy,
)
```

The returned frozen bundle exposes `begin_oidc_authorization` and
`complete_oidc_authorization`. Both preserve the existing IAM presenter
`handle(context=..., command=...)` contract and can be assigned directly to
the corresponding `IamHttpPresenterBindings` fields.

The OIDC provider must be `ClosedOidcProvider` (or an implementation with the
same closed contract). Its `preflight_exchange` resolves and validates both
discovery metadata and JWKS before the database claim commits. Only after a
claim commit is known to have succeeded may the one-time authorization code be
sent to the provider.

## Secret and failure boundaries

Raw state, browser binding cookie, authorization code, provider tokens, raw
subject, Session handle, and CSRF token never enter PostgreSQL requests,
receipts, audit attributes, or object representations. PostgreSQL receives
only keyed 32-byte digests, encrypted nonce/verifier evidence, verified subject
digest facts, and new Session/CSRF digests.

If claim commit acknowledgement is lost, the handler returns
`COMMAND_OUTCOME_UNKNOWN` and does not call the provider. If final Session
commit acknowledgement is lost, the handler returns no Session or CSRF secret
and never repeats the provider exchange. A provider-rejected or invalid
verified subject is settled to a rejected terminal transaction before the
request fails. The database, not the caller, derives the transaction deadline
as exactly ten minutes; a finalize that reaches the database after that
deadline is also atomically rejected instead of leaving an exchange stranded.

The OIDC callback remains a protocol exception: it has no replayable command
receipt and a terminal callback cannot recreate raw cookie material.

## Verification evidence

The production-bound test suite includes:

- frozen bundle and presenter-compatible handler contracts;
- provider metadata/JWKS preflight before claim;
- real PostgreSQL 18 begin, process restart, callback lookup, claim, finalize,
  Session creation, and replay closure;
- two-connection claim concurrency with exactly one winner;
- real commit-acknowledgement loss and `COMMAND_OUTCOME_UNKNOWN` behavior;
- wrong browser, unknown subject, frozen issuer, and FORCE RLS negative paths.
