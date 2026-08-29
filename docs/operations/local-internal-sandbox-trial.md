# Local INTERNAL_SANDBOX trial manager

This command provides a repeatable, local-only way to build the current checkout, open the ten bootstrapped synthetic role accounts, and exercise one provider-only invited identity. It is not a release, migration approval, production deployment, or real-user environment. The resulting stack keeps `external_participants=false` and publishes only `127.0.0.1:443`.

The current static pointer is [current-head v27](/operations/current-head-v27.md), on IAM46 / Profile5 / Demand15 / Trust22 / Matching3 / Taxonomy2. It adds the independent durable Matching runtime and selector/reviewer workbenches and remains `STATIC VERIFIED / NOT PRODUCTION EXECUTED`; no v27 fresh-volume, migration, backup/restore, or production execution is recorded. The separate fresh-volume synthetic acceptance below is frozen historical v25 runtime/source evidence and cannot be relabeled as v26, v27, or production. The exact v24 runtime and source acceptance also remains frozen historical evidence and cannot be relabeled as v25, v26, v27, production, or a real-data upgrade. The v23 and v22 local runs remain frozen historical evidence.

The manager is intentionally non-destructive. It has `prepare`, `status`, `start`, `resume`, and `stop`; it has no cleanup command. It never removes containers, networks, volumes, images, inputs, logs, or receipts. `stop` preserves all five successful one-shot containers and their logs, the five persistent containers, four networks, and the PostgreSQL volume. Every newly created container must have an exact Docker `local` log configuration of `max-size=10m`, `max-file=3`, and `compress=true`; the nominal limit is about 30 MiB per container. Existing frozen v24 containers are not recreated or backfilled. Rotation is not Audit, centralized logging, alerting, backup, or sensitive-data erasure.

## Prerequisites and coordinates

Run from the repository checkout after creating `platform/.venv` with the locked platform dependencies. Docker must use a local Unix-socket context. Choose all coordinates explicitly and keep them unique. The root and the three application image tags must not already exist; the four private `/24` networks must not overlap any existing Docker network.

The TLS fixture currently fixes the two names `pilot.example.test` and `identity.example.test`, so `--domain` must be exactly `example.test`.

```bash
export DESIRE_LOCAL_ROOT="$PWD/secrets/local-current-trial-01"
export DESIRE_LOCAL_PROJECT="desire-local-current-trial-01"
export DESIRE_LOCAL_TAG="local-current-trial-01"

local_trial() {
  python3 -B scripts/manage_local_internal_sandbox.py "$@" \
    --root "$DESIRE_LOCAL_ROOT" \
    --project-name "$DESIRE_LOCAL_PROJECT" \
    --image-tag "$DESIRE_LOCAL_TAG" \
    --domain example.test \
    --ingress-cidr 172.28.240.0/24 \
    --oidc-cidr 172.28.241.0/24 \
    --app-cidr 172.28.242.0/24 \
    --data-cidr 172.28.243.0/24
}
```

These CIDRs are examples, not defaults. The manager rechecks project labels, exact resource names, image tags, network overlap, and the loopback listener before consuming fresh coordinates.

## Prepare and start once

`prepare` exclusive-creates the private `0700` root, delegates to the existing secret/input, TLS, runtime-bundle, and Compose-input generators, verifies their outputs, and writes a non-secret receipt under `.local-internal-sandbox/`. The receipt binds a canonical digest of the Dockerfile and the exact Platform/Web/Edge source set, plus the Git HEAD, dirty flag, tracked-diff digest, untracked-content digest, and porcelain-status digest. `start` refuses any change to that evidence after preparation. The manager independently requires the generated deployment configuration to use issuer `https://identity.example.test`, client ID `desire-internal-sandbox`, callback `https://pilot.example.test/v1/auth/oidc/callback`, and the synthetic DNS-only network binding. It never prints secret material.

```bash
local_trial prepare
local_trial status
```

The expected state is `PREPARED`. The root is consumed even if preparation fails; preserve it for diagnosis and use entirely new coordinates for any later trial.

`start` is also single-use. It validates the resolved Compose configuration, the pinned PostgreSQL image digest, exact commands and mount attachments, closed users and security settings, and requires the only published port to be `127.0.0.1:443`. It builds the Platform/Web/Edge images under the fresh tag, rechecks the complete source binding, and runs Compose `up --no-build --pull never -d --wait`. Resolved and live validation reject added capabilities, devices, group additions, privileged/host namespaces, writable or unexpected bind mounts, any non-database writable root filesystem, or a `HostConfig.LogConfig` other than the exact bounded policy above. The PostgreSQL volume must use the local driver and local scope. It then requires all five one-shot services to be `exited|0` with restart policy `no`, and validates exactly one JSON log result from each:

- fresh schema application with no skipped migrations;
- fresh taxonomy seed;
- online credential reconcile and verify;
- applied and verified ten-account identity bootstrap, while the eleventh provider-only identity remains absent from bootstrap roles and authority.

Only after all ten containers, four networks, the PostgreSQL volume, image IDs, live security projections, health states, and one-shot logs validate does it write the immutable start receipt. The final gate also reads the API readiness contract inside the receipt-bound API container and tests the browser path over loopback TLS: the exact OIDC discovery document, RS256 JWKS, and pilot homepage must all be available through the generated CA. A fresh start additionally completes one synthetic authorization-code/PKCE exchange using the pinned `desire-internal-sandbox` client, exact callback, and file-backed client secret; neither the secret nor the returned short-lived tokens are printed or written. `status` repeats the non-consuming browser-facing checks whenever it reports `HEALTHY`.

```bash
local_trial start --wait-timeout 180
local_trial status
```

The expected state is `HEALTHY`. A start-side failure returns `LOCAL_INTERNAL_SANDBOX_PARTIAL_POSSIBLE`; do not rerun `start`, remove resources, or reuse any of its root/project/tag/CIDR coordinates. Preserve the root and Docker state for inspection.

Automated journey state and result files must be written to a new private evidence directory outside both `DESIRE_LOCAL_ROOT` and the repository. The manager seals the complete input tree at `prepare`; adding evidence anywhere below that root correctly makes later `status` and `resume` fail closed. The E2E runner rejects an output path below any manager root containing `.local-internal-sandbox/prepared-receipt.json` before it performs a login or business action. For example:

```bash
export DESIRE_LOCAL_EVIDENCE_ROOT="/private/tmp/desire-local-current-trial-01-evidence"
umask 077
mkdir -m 0700 "$DESIRE_LOCAL_EVIDENCE_ROOT"
python3 -B scripts/run_internal_sandbox_e2e.py journey \
  --ca-file "$DESIRE_LOCAL_ROOT/internal-sandbox-tls/root-ca.pem" \
  --state-output "$DESIRE_LOCAL_EVIDENCE_ROOT/state.json" \
  --result-output "$DESIRE_LOCAL_EVIDENCE_ROOT/journey-result.json"
```

The evidence directory is durable for the trial and must not be reused, overwritten, moved into the input root, or removed by this workflow.

## Historical v25 checkout local synthetic dynamic acceptance（2026-08-26）

The IAM42 / Profile3 / Demand12 / Trust18 / Taxonomy2 runtime and source bound by a fresh manager receipt completed one isolated synthetic local trial. Only de-identified documentation records were added after the final `STOPPED` result; application, Docker, migration, and runtime source were not changed. This record omits every root, project, image tag, CIDR, object identifier, and authentication identifier:

- the manager advanced from `PREPARED` to `HEALTHY` on a fresh PostgreSQL volume, with all five one-shot containers successful and all five persistent containers healthy;
- the ten-account, eight-duty journey returned `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`, and the independent provider-only invited Demand Owner journey returned `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`;
- the receipt-bound Web included an editor-wide write lock for in-flight and outcome-unknown mutations, exact read-only Finance task handoff for continue/wait actions, and timezone-safe Organization invitation expiry conversion. Web production build and `206` tests passed; the deployment suite passed `549` tests, the unchanged Platform suite retained its `1935`-test GREEN result, and the v25 static verifier passed;
- sampled recent live API boundary entries contained only the closed `HTTP_BOUNDARY_OBSERVATION_V1` fields; the sample contained no raw target, query, header, body, actor, object, trace, or exception text. Manager health checks also verified every created container used the exact Docker `local` / `10m` / `3` / compressed logging contract;
- after a controlled `STOPPED -> resume -> HEALTHY`, the restart verifier returned `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN` and rediscovered the terminal Finance, Trust, Appeal, Organization, account, Profile, and Demand facts from the retained database;
- the final manager state was `STOPPED`. Ten receipt-bound containers, four networks, the PostgreSQL volume, application images, and four `0600` evidence JSON files inside a `0700` directory remain retained. No `down`, delete, remove, `--rm`, or prune operation was used;
- the in-app Browser could not reach the host-loopback synthetic HTTPS service and reported a closed/unreachable connection. No CA trust was installed, no certificate warning was bypassed, and no host or system trust configuration was changed. Complete desktop/mobile visual QA therefore remains explicitly open.

This is synthetic, local, fresh-volume dynamic evidence for the historical v25 checkout only. It is not a production migration, production deployment, release authorization, real-data upgrade proof, backup/restore result, real-provider validation, or complete visual QA result. The frozen current-head v25 publication remains `STATIC VERIFIED / NOT PRODUCTION EXECUTED` with `production_authorized=false`; this record is not v26 dynamic evidence.

## Frozen v24 local dynamic acceptance evidence (2026-08-26)

The IAM42 / Profile3 / Demand12 / Trust18 / Taxonomy2 runtime and source completed one fresh, isolated synthetic local trial. Only this de-identified documentation record was added after the final `STOPPED` result. It omits every root, project, image tag, CIDR, object identifier, and authentication identifier:

- the manager advanced from `PREPARED` to `HEALTHY` on a fresh PostgreSQL volume, with all five one-shot containers successful and all five persistent containers healthy;
- the ten-account journey returned `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`, including the Appeal Reviewer completed-history list, exact terminal detail, completed task, wrong-role `404`, query rejection, and a second reviewer's empty actor-owned history plus foreign-detail `404`; the temporary second-reviewer duty was reconciled to its original role;
- the independent provider-only invited Demand Owner journey returned `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`;
- after a controlled `STOPPED -> resume -> HEALTHY`, the restart verifier returned `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN` and rediscovered the terminal Trust and Appeal facts from the retained database;
- the final manager state was `STOPPED`; the ten receipt-bound containers, four networks, PostgreSQL volume, application images, and four private evidence JSON files remain retained. No `down`, delete, remove, `--rm`, or prune operation was used;
- the verified repository suites were Platform `1929`, Web `200` including its production build, and deployment `536`; the v24 static verifier and 103-page documentation verifier also passed;
- the in-app Browser could not bridge its isolated `localhost` to the host Docker loopback. The temporary host mapping was restored byte-for-byte, no CA trust was installed, and no certificate warning was bypassed. Therefore full desktop/mobile visual QA remains explicitly open even though the real HTTPS/API journey and Web interaction contracts are green.

This is synthetic, local, fresh-volume dynamic evidence only. It is not a production migration, production deployment, release authorization, real-data upgrade proof, backup/restore result, or complete visual QA result. The frozen current-head v24 publication retains its original `STATIC VERIFIED / NOT PRODUCTION EXECUTED` claim; frozen current-head v25 and current-head v26 are likewise static-only and not production executed.

## Historical v23 local dynamic acceptance evidence (2026-08-26)

The then-current IAM42 / Profile3 / Demand12 / Trust17 / Taxonomy2 runtime and source completed one fresh, isolated synthetic local trial. Only de-identified documentation records were added after the final `STOPPED` result; no application, Docker, migration, or runtime source changed. This record intentionally omits every root, project, tag, CIDR, object identifier, and authentication identifier:

- the manager advanced from `PREPARED` to `HEALTHY` on a fresh PostgreSQL volume, with all five one-shot containers successful and all five persistent containers healthy;
- the ten-account journey returned `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`;
- the independent provider-only invited Demand Owner journey returned `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`;
- after a controlled `STOPPED -> resume -> HEALTHY`, the restart verifier returned `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`; its summary proved `trust_terminal_history_discoverable=true` and `terminal_history_actor_scoped=true`;
- the final manager state was `STOPPED`. Exactly ten containers, four networks, one PostgreSQL volume, and three application images remain retained, and every container has `RestartCount=0`;
- four distinct evidence JSON files remain retained as `0600` regular files. No `down`, delete, remove, or cleanup operation was used.

This is synthetic, local, fresh-volume dynamic evidence only. It is not a production migration, production deployment, release authorization, real-data upgrade proof, backup/restore result, or visual QA result. The current-head v23 publication remains `STATIC VERIFIED / NOT PRODUCTION EXECUTED`.

## Historical local dynamic acceptance evidence (2026-08-25)

On 2026-08-25, a fresh isolated trial of the then-current checkout produced the following local dynamic evidence:

- the fresh database migration reached IAM `0040` and Trust `0013`, and the manager reported `HEALTHY`;
- the complete journey for the ten bootstrapped synthetic role accounts passed;
- a provider-only identity began as pending with no role, workspace, user role, or platform duty; after accepting its exact invitation, it received only `DEMAND_OWNER` in the target organization;
- the invitation-created Demand Owner remained hidden from the administrative route with `404`, while Demand create, idempotent replay, cancel, and completed-history reads all passed;
- the database projection contained 11 active users, zero pending users, and 11 external identities; the invitation-created identity had the one target-organization role and no user role or platform duty;
- the manager completed `STOPPED -> resume -> HEALTHY`, the restart verifier passed, and the final state returned to `STOPPED` with the containers, networks, one-shot evidence, and PostgreSQL volume preserved.

This is historical local dynamic acceptance evidence for the then-tested checkout. It does not turn the current-head v19 static contract into an executed release, approve a migration for production, or replace desktop/mobile visual QA, backup/restore, PITR, alerting, and real-provider validation.

## Historical frozen v22 local dynamic acceptance evidence (2026-08-26)

The then-current IAM42 / Profile3 / Demand12 / Trust16 / Taxonomy2 runtime and source code, followed only by that de-identified documentation update, completed a fresh isolated trial:

- all five one-shot services exited successfully and all five persistent services reached `HEALTHY` on a fresh volume;
- the ten-account journey returned `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`, including temporary platform-duty grant/revoke behavior and actor-scoped, paged Finance terminal history;
- the separate provider-only journey returned `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`, granting only the target organization's `DEMAND_OWNER` authority;
- the manager completed `HEALTHY -> STOPPED -> resume -> HEALTHY -> STOPPED`; the restart verifier returned `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`, did not rerun a one-shot, and rediscovered the Finance, Trust, Appeal, account, and organization terminal facts;
- an earlier trial wrote evidence below the sealed input root and correctly failed closed on subsequent status. The runner now rejects direct and ancestor-symlink output paths below a manager input root before login. A second isolated trial exposed an unregistered restart-history failure stage; that stack was also stopped and preserved, and a third fresh coordinate set completed the green sequence;
- all containers, networks, volumes, images, receipts, result files, and failed-trial evidence remain retained; no cleanup or destructive Docker command was used.

This frozen evidence is synthetic and fresh-volume only. It does not replace a quiesced real-data IAM42 preflight, production migration approval, desktop/mobile visual QA, backup/restore, PITR, alerting, encrypted off-host backup, or real-provider validation, and it is not v23/Trust17, v24/Trust18, historical v25/Trust18, or current-head v26 dynamic evidence.

## Try the synthetic roles

For a browser trial, resolve both fixed names to loopback in a local-only test configuration and trust only this trial's root CA:

```text
127.0.0.1 pilot.example.test identity.example.test
```

The CA is at `$DESIRE_LOCAL_ROOT/internal-sandbox-tls/root-ca.pem`. Install it only in a dedicated test browser profile or test trust store, then open `https://pilot.example.test`. Never install this synthetic CA as a system-wide or production trust anchor.

For a focused role acceptance check, use only the synthetic data created inside this trial:

1. As Organization Admin, issue a `DEMAND_OWNER` invitation to `sandbox-invited-demand-owner-02@example.test`. In a signed-out browser, open that invitation and choose `invited_demand_owner_02` at the synthetic provider. Before acceptance, confirm the account is pending and has no role or workspace; after policy confirmation and invitation acceptance, confirm it has only the target organization's Demand Owner role, then create and cancel a Demand and verify its read-only completed history.
2. As the original Demand Owner, take one eligible Demand to `FUNDED`, cancel it with one of the offered closed reasons, and confirm the page becomes `CANCELLED`, read-only, and visible in completed history.
3. As Trust Officer, open “My tasks and history”, confirm one of that officer's completed cases appears with only the party-safe summary, and use it to return to the Trust workspace without pasting a resource identifier.
4. As each Finance Operator, finish the two-person synthetic funding review, confirm it disappears from the active queue, then open “我的已完成资金审查”. Both confirmers must rediscover the `SECURED` review; a terminal finding must be visible only to the operator who submitted it. Open a row without pasting a review identifier and confirm the detail matches the review, Demand version, terminal status, and ETag.
5. After the stop/resume sequence below, sign in again and confirm the invitation-created account and all three role histories are still readable. This focused check does not replace a complete desktop/mobile visual review.

## Stop, inspect, and resume

`stop` deliberately uses a containment-only validator: it requires the immutable receipt, exact project/service labels, exact receipt-bound image IDs, commands/users, networks, mounts, and recorded live security projections, then stops only the five receipt-bound persistent container IDs in Web → API → Edge → synthetic OIDC → database order. It does not depend on current mutable image tags, one-shot readiness, or healthy/zero-exit persistent state, so an unhealthy, starting, restarting, or failed persistent container can still be contained. Repeated `stop` is harmless.

```bash
local_trial stop
local_trial status
```

The expected state is `STOPPED`. `resume` never calls Compose `up` and cannot create or recreate anything. It starts only the five existing receipt-bound IDs in dependency order, waits for each to become healthy, and never reruns a one-shot.

```bash
local_trial resume --wait-timeout 180
local_trial status
```

After a successful resume, the expected state is `HEALTHY`. Re-read the focused role history above before stopping the trial again.

```bash
local_trial stop
local_trial status
```

The final expected state is `STOPPED`; the retained volume and other receipt-bound resources are the persistence evidence and must not be removed by this workflow.

`RECOVERABLE` means a verified mix of healthy and stopped persistent containers; `resume` or `stop` can converge that state without creating resources. `START_INCOMPLETE`, `PREPARATION_INCOMPLETE`, a blocked status call, or `LOCAL_INTERNAL_SANDBOX_PARTIAL_POSSIBLE` requires manual read-only diagnosis. The manager deliberately offers no automated cleanup or repair path.
