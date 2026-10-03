# EA-O5-EXP-v0.1 — pre-registration package

Status: **ONE STEP FROM FROZEN.** The contract (`CONTRACT.pdf`), the analysis, the registries and the
verifier source are final. One freeze blocker is left by design: `verifier/BUILD_RECORD.json`, which
`verifier/build_and_lock.sh` writes on a machine with Maven Central access (the authoring environment
could not reach it). Until then `analysis.py` returns `NOT_FROZEN`; `test_shipped_registry_is_not_frozen`
checks that this is the only blocker; after the build, `test_shipped_package_is_frozen` replaces it.

## Pinned decisions

- **IdP:** Keycloak 26.7.5 (tag 26.7.5, commit 44299f3, 2026-09-30). Default access-token lifetime
  300 s from `Constants.java:59`, applied to new realms by `DefaultExportImportManager.java:251-252`.
  Source files are archived in `provenance/` with `PROVENANCE.sha256`.
- **Realm rule:** the runs use a non-master realm created without `accessTokenLifespan` and with no
  client attribute `access.token.lifespan`. The master realm is excluded because
  `ApplianceBootstrap.java:87` gives it 60 s. The realm export is deposited with the runs.
- **DPoP (control arm):** issued by Keycloak by default in 26.7.5 (`Profile.java:127`, `Type.DEFAULT`).
  Verified at the gateway by a DPoP verifier service on Spring Security 7.1.1 (Spring Boot 4.1.1),
  called through Envoy ext_authz in both arms; local JWT validation, no introspection, no revocation
  lookup. Checks: proof signature and typ, htm, htu, iat (30 s), cnf.jkt, ath, jti replay, and
  rejection of a DPoP-bound token sent as Bearer. `htu` is the external URL (frozen rule in `sources.yaml`).
- **Gateway:** Envoy Proxy 1.38.5 (commit 4be7862, 2026-10-01). `jwt_authn` validates JWTs locally
  from the realm JWKS (signature, iss, aud, exp, nbf); no introspection or per-request revocation call.
  Shipped clock skew 60 s, not overridden, so a JWT is accepted until exp + 60 s. c3b is an RBAC DENY
  policy. Filter sources archived in `provenance/`.
- **Queue:** RabbitMQ 4.3.6 (commit 7a34a0c); durable queue, persistent messages.
- **Gate rule:** `gate_pass` at the earliest poll at which the role is verified, no applicable
  GlobalBlock is active, and at least m_K complete footprint chains are readable; m = 1/2/3/4 for
  K1–K4. With the frozen footprints this equals the full footprint for c2–c5; only c1 (K1, two
  chains) can pass on one chain, and E1 is readable at the alert.
- **Run parameters (`frozen_config.json`):** δ_p = 100 ms, q = 0.50, N = 30 baseline per arm,
  20 oracle and 30 correction runs per correction and arm.
- **Authority:** `R_AGENT_OPERATOR` (c1), `R_WORKFLOW_OPERATOR` (c2, c5), `R_IDENTITY_SECURITY_ADMIN`
  (c3a), `R_GATEWAY_SECURITY_ADMIN` (c3b), `R_INCIDENT_CONTAINMENT_ADMIN` (c4). *The authority role
  is checked, not acquired, during the run*: all roles are provisioned before the first run, so
  tau_gate never contains provisioning or human approval time. `k_rule` is unchanged; K(c) is not
  the authority tier.

Contract: *EA-O5 Experimental Contract v0.1* (Claude Docs). Export it to `CONTRACT.pdf`
and add it to this folder at freeze time.

## Files

| File | Role |
| --- | --- |
| `MANIFEST_SCHEMA.json` | JSON Schema of the raw run manifest: `frozen` configuration + `runs` observations. No category field exists. |
| `corrections.yaml` | Correction registry: K class, arms, evidence footprint (serial chains), authority, GlobalBlock applicability. S is not here; it is measured. |
| `sources.yaml` | Provenance of every timing input: measured or imposed, scope (primary or secondary), source. |
| `analysis.py` | Deterministic analysis. Reads the manifest and registries, writes `analysis_output.json`. Makes no modelling decisions. |
| `test_analysis.py` | Synthetic unit tests: one per outcome category, plus freeze and kill-criterion guards, plus an exhaustive check that the categories partition all cases. |
| `provenance/` | Keycloak 26.7.5 source files cited for the token lifetime, the realm rule and DPoP, with `PROVENANCE.sha256`. |
| `conformance.yaml` | Seven token-path conformance tests (CT1–CT7) with expected decisions, 5 repetitions each, run before the first and after the last run; the artifacts whose hashes must not change between the two. |
| `CONTRACT.pdf` | EA-O5 Experimental Contract v0.1, final text, formulas typeset (10 pages, A4). |
| `contract_src/` | Source of `CONTRACT.pdf`: the contract as markdown and `build_contract_pdf.sh` (pandoc 3.1.3, KaTeX 0.16.47, Chromium). The markdown is the text of record. |
| `verifier/` | DPoP verifier service: source (`src/`), build file (`pom.xml`, versions from Spring Boot 4.1.1), service-level tests of CT1–CT7 and boundaries, `build_and_lock.sh`. After the build: `dist/eao5-dpop-verifier.jar`, `dependencies.lock`, `BUILD_RECORD.json`. |
| `frozen_config.json` | The manifest `frozen` block, deposited before any run. The run manifest's `frozen` block must equal it field by field (except the declared window). |
| `MANIFEST.sha256` | SHA-256 of every file above. |

## Statuses

- `INVALID_MANIFEST`: the manifest fails the schema (e.g. q outside [0,1], non-positive poll interval, malformed log hash).
- `NOT_FROZEN`: the manifest's frozen block differs from `frozen_config.json`, the gate thresholds are not strictly increasing in K or exceed a footprint, a frozen field or registry entry is TBD (including `gate_rule`, `realm_rule`, the authority rule), a correction's role is not a defined role, a registry file hash differs, or the token lifetime in the manifest does not match `sources.yaml`.
- `ANALYSED`: an outcome category was computed.

## Rules implemented literally in `analysis.py`

- **Exact counts.** `n_baseline_per_arm`, `n_oracle_per_correction`, `n_correction_per_correction` are frozen; any other number of runs (added or withheld) makes the study VOID.
- **Token lifetime cross-check.** `frozen.token_lifetime_default_s` must equal `sources.yaml` `token_lifetime_self_hosted.value`, and `frozen.token_lifetime_source` must equal its `source`; its provenance block (software version, documentation version, access date, verbatim statement, archived artifact hash) must be complete.
- **Integrity and ordering (VOID).** Duplicate run_id; unknown correction_id or one not registered for the arm; baseline run without X2 or with X2 not after the alert; oracle run without a boolean verdict; token exp not after issue; gate before alert; execution before gate; effect before gate or execution; evidence readable before its event; duplicate evidence items in one run.
- **Condition (iii) semantics (frozen: `aggregate`).** (iii) is evaluated on the median tau_exec and median tau_tot per correction. A run-paired diagnostic (share of runs with tau_exec <= W and tau_tot > W) is always reported; for PASS-O5 or GATE-TOTAL the output states whether the run-paired rule agrees for at least one attributing correction (`attribution_stable_run_paired`). The diagnostic never changes the category; a PASS-O5 is reported as robust only if it agrees.

- **Window.** W = nearest-rank quantile q of (t_x2 − t_jdagger) over the arm's baseline runs. No interpolation. A declared window that differs from the computed one makes the study VOID.
- **Per correction, per arm.** tau_gate = gate_pass − t_jdagger (infinite if never passed, or if GlobalBlock applies and is active); tau_exec = effect − gate_pass; tau_tot = tau_gate + tau_exec. Aggregate: median over the correction runs.
- **Evidence.** d(e) = first_readable − event; a chain's duration is the sum of d(e) along it; tau_acq = the m_K-th smallest chain duration. Reported.
- **Gate-rule compliance (VOID).** For every correction run not under GlobalBlock, the time at which m_K chains are completely readable is computed from the logged timestamps. A gate pass before that time, or more than one poll interval after it, makes the study VOID: the first bypasses the threshold, the second inflates tau_gate.
- **Sufficiency.** S(c) = 1 iff every oracle run of c prevented X2.
- **Sets.** C_timely = {c : tau_tot ≤ W}; C_suff = {c : S(c) = 1}.
- **Precedence (literal).** VOID → FAIL-NOSUFF → FAIL-EXEC → GATE-TOTAL → PASS-O5 → FAIL.
- **Pre-registered verifier.** Freeze requires `verifier/BUILD_RECORD.json`, and the source tree, jar and lock must match it. The verifier hashes recorded at both conformance tests must equal it, otherwise VOID.
- **Conformance (VOID).** The manifest's `conformance` block must show every test of `conformance.yaml` with its expected decision in every repetition, before the first run and after the last run, with identical artifact hashes.
- **VOID triggers.** Token lifetime override; any run whose token lifetime differs from the frozen default by more than 1 s; hand-set window; missing baseline, oracle or correction runs; control arm not in category FAIL.
- **Lever arm.** Reported only; never changes the primary outcome.
- **Consistency report.** Correction runs where the predicted prevention (timely and sufficient) disagrees with the observed X2 are listed. They do not change the category.

## Freeze procedure

1. On a machine with Maven Central access (JDK 21, Maven 3.9+): `verifier/build_and_lock.sh`. It runs the
   verifier tests, builds twice and requires identical jars, then writes `dist/eao5-dpop-verifier.jar`,
   `dependencies.lock` and `BUILD_RECORD.json`. If a verifier test fails, fix it before deposit: the source is
   not frozen until this step succeeds.
2. In `test_analysis.py` set `EXPECT_FROZEN = True`, then run `python3 -m unittest -v test_analysis.py`;
   all tests must pass. This switches from `test_shipped_registry_is_not_frozen` (now skipped) to
   `test_shipped_package_is_frozen`, which recomputes the source-tree, jar and lock hashes independently,
   checks them against `BUILD_RECORD.json`, and requires the analysis to report no freeze blocker.
3. Regenerate `MANIFEST.sha256` (every file except itself, including `provenance/` and `verifier/`, excluding
   `verifier/target/`) and deposit the folder (e.g. Zenodo) **before any run**. From here no frozen artifact changes.
4. Build the testbed on the pinned stack with the deposited jar. Run the conformance tests of
   `conformance.yaml` and record results and artifact hashes in the manifest's `conformance.pre` block.
   Any failure stops the study before the first run.
5. For the runs, copy `frozen_config.json` into the manifest's `frozen` block unchanged.
6. After the last run, repeat the conformance tests into `conformance.post`.
7. Any later change to a frozen file opens EA-O5-EXP-v0.2.

## Running the analysis

```
python3 analysis.py run_manifest.json --out analysis_output.json
```

Requires Python 3.10+, `PyYAML`, `jsonschema`.
