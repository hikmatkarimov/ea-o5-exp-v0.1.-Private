#!/usr/bin/env python3
"""Synthetic unit tests for analysis.py: one test per outcome category, plus freeze
and kill-criterion guards. Run: python3 -m unittest test_analysis.py

These tests are part of the frozen package. Their purpose is to show that the
analysis logic was fixed before any real run and is not adjusted to results.
"""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import yaml

import analysis

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE / "MANIFEST_SCHEMA.json").read_text())
S = 1000  # ms per second
W_S = 60  # synthetic window: 60 s
TOKEN_S = 300

# Freeze switch (README, freeze procedure step 2). False until verifier/build_and_lock.sh has written
# verifier/BUILD_RECORD.json; then set to True, so the positive freeze test runs and the pre-build test is
# skipped. Both tests stay in the file, and `unittest -v` shows which state was verified.
EXPECT_FROZEN = False


def filled_registry(tmp: Path) -> tuple[Path, Path, dict, dict]:
    """Copies of the registry files with every TBD filled, so the freeze check passes."""
    corr = yaml.safe_load((HERE / "corrections.yaml").read_text())
    corr["gate_rule"] = "synthetic gate rule"
    for c in corr["corrections"]:
        assert c["required_authority"] in corr["authority_roles"], c["id"]
    src = yaml.safe_load((HERE / "sources.yaml").read_text())
    for s in src["inputs"]:
        if s["parameter"] == "token_lifetime_self_hosted":
            s["source"] = "synthetic citation"
            s["value"] = TOKEN_S
            s["provenance"] = {"software_version": "idp 1.0", "documentation_version": "1.0",
                               "access_date": "2026-10-03", "exact_statement": "default 300 s",
                               "artifact_sha256": "0" * 64}
            s["realm_rule"] = "synthetic realm rule"
        if s["parameter"] == "dpop_enforcement":
            s["source"] = "synthetic verifier"
            s["value"] = "synthetic"
    cp, sp = tmp / "corrections.yaml", tmp / "sources.yaml"
    (tmp / "conformance.yaml").write_bytes((HERE / "conformance.yaml").read_bytes())
    synthetic_verifier_build(tmp / "verifier")
    cp.write_text(yaml.safe_dump(corr))
    sp.write_text(yaml.safe_dump(src))
    return cp, sp, corr, src


def evidence(t0: int) -> list[dict]:
    return [{"item": f"E{i}", "event_ms": t0, "first_readable_ms": t0 + i * S} for i in range(1, 8)]


def run(run_id, arm, kind, cid=None, gate_s=None, exec_s=None, x2=True, oracle_prevents=None, x2_at_s=None):
    t0 = 1_000_000
    gate = None if gate_s is None else t0 + int(gate_s * S)
    eff = None if (gate is None or exec_s is None) else gate + int(exec_s * S)
    return {
        "run_id": run_id, "arm": arm, "kind": kind, "correction_id": cid,
        "t_jdagger_ms": t0, "t_x2_ms": None if x2_at_s is None else t0 + int(x2_at_s * S),
        "token_issue_ms": t0 - 10 * S, "token_exp_ms": t0 - 10 * S + TOKEN_S * S,
        "global_block_active": False,
        "gate_pass_ms": gate, "execution_start_ms": gate, "effect_ms": eff,
        "x2_observed": x2, "oracle_prevents_x2": oracle_prevents,
        "evidence": evidence(t0) if gate is None else [
            {"item": f"E{i}", "event_ms": t0, "first_readable_ms": gate} for i in range(1, 8)],
        "log_hashes": {"gateway": "0" * 64},
    }


def build_manifest(spec: dict, cp: Path, sp: Path) -> dict:
    """spec[arm][cid] = (gate_s, exec_s, sufficient)."""
    runs = []
    for arm, table in spec.items():
        for i in range(3):
            runs.append(run(f"{arm}-base-{i}", arm, "baseline", x2=True, x2_at_s=W_S))
        for cid, (g, e, suff) in table.items():
            runs.append(run(f"{arm}-oracle-{cid}", arm, "oracle", cid, x2=not suff, oracle_prevents=suff))
            timely = g + e <= W_S
            runs.append(run(f"{arm}-corr-{cid}", arm, "correction", cid, g, e, x2=not (timely and suff)))
    return {
        "study_id": "synthetic",
        "contract_version": "EA-O5-EXP-v0.1",
        "frozen": {
            "stack": {"stack_id": "s1", "idp_name": "idp", "idp_version": "1.0", "gateway_name": "gw",
                      "gateway_version": "1.0", "queue_name": "q", "queue_version": "1.0"},
            "token_lifetime_default_s": TOKEN_S,
            "token_lifetime_source": "synthetic citation",
            "token_lifetime_override": False,
            "poll_interval_ms": 250,
            "window_rule": {"type": "quantile_of_baseline", "q": 0.5},
            "tau_aggregate": "median",
            "oracle_rule": "all_oracle_runs_prevent",
            "n_baseline_per_arm": 3,
            "n_oracle_per_correction": 1,
            "n_correction_per_correction": 1,
            "cond_iii_semantics": "aggregate",
            "corrections_file_sha256": hashlib.sha256(cp.read_bytes()).hexdigest(),
            "sources_file_sha256": hashlib.sha256(sp.read_bytes()).hexdigest(),
            "conformance_file_sha256": hashlib.sha256((cp.parent / "conformance.yaml").read_bytes()).hexdigest(),
        },
        "runs": runs,
        "conformance": passing_conformance(cp.parent / "conformance.yaml"),
    }


def synthetic_verifier_build(vdir: Path) -> dict:
    """The real verifier sources with a stand-in jar and lock, recorded as build_and_lock.sh would."""
    import shutil
    shutil.copytree(HERE / "verifier", vdir, ignore=shutil.ignore_patterns("target", "dist", "BUILD_RECORD.json",
                                                                          "dependencies.lock"))
    (vdir / "dist").mkdir()
    (vdir / "dist" / "eao5-dpop-verifier.jar").write_bytes(b"synthetic jar")
    (vdir / "dependencies.lock").write_text("0" * 64 + "  synthetic.jar\n")
    rec = {"verifier_source_tree_sha256": analysis.source_tree_sha256(vdir),
           "verifier_jar_sha256": hashlib.sha256(b"synthetic jar").hexdigest(),
           "verifier_build_lockfile_sha256": hashlib.sha256((vdir / "dependencies.lock").read_bytes()).hexdigest(),
           "reproducible": True}
    (vdir / "BUILD_RECORD.json").write_text(json.dumps(rec))
    return rec


def passing_conformance(path: Path) -> dict:
    """Pre- and post-run conformance blocks in which every test gives its expected decision."""
    conf = yaml.safe_load(path.read_text())
    arts = {a: "a" * 64 for a in conf["artifacts_hashed"]}
    rec_path = path.parent / "verifier" / "BUILD_RECORD.json"
    if rec_path.exists():
        rec = json.loads(rec_path.read_text())
        for art, key in analysis.VERIFIER_HASH_KEYS.items():
            arts[art] = rec[key]
    def phase(ms):
        return {"performed_ms": ms, "artifact_sha256": dict(arts),
                "results": [{"test_id": t["id"], "repetition": i, "decision": t["expected"]}
                            for t in conf["tests"] for i in range(1, conf["repetitions"] + 1)]}
    return {"pre": phase(1), "post": phase(10**12)}


# Arm tables. Tuples are (gate_s, exec_s, sufficient); W = 60 s.
CONTROL_OK = {  # DPoP arm: tool restriction suffices -> FAIL (no truncation), as required
    "c1": (5, 2, True), "c2": (10, 3, False), "c3a": (40, 3600, True), "c3b": (90, 5, True), "c4": (200, 10, True),
}
LEVER_OK = dict(CONTROL_OK, c1=(5, 2, False), c5=(8, 2, True))
PASS_PRIMARY = {
    "c1": (5, 2, False), "c2": (10, 3, False), "c3a": (40, 3600, True), "c3b": (90, 5, True), "c4": (200, 10, True),
}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cp, self.sp, self.corr, self.src = filled_registry(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def outcome(self, primary, control=CONTROL_OK, lever=LEVER_OK, mutate=None):
        m = build_manifest({"primary": primary, "control": control, "lever": lever}, self.cp, self.sp)
        if mutate:
            mutate(m)
        # The deposited frozen config is whatever the (possibly mutated) manifest declares,
        # so these tests exercise the post-freeze rules; the mismatch case is tested separately.
        return analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))


class TestCategories(Base):
    def test_pass_o5(self):
        r = self.outcome(PASS_PRIMARY)
        self.assertEqual(r["primary_outcome"], "PASS-O5", r.get("void_reasons"))
        self.assertEqual(r["arms"]["control"]["category_raw"], "FAIL")
        self.assertEqual(r["arms"]["lever"]["category_raw"], "FAIL")
        self.assertEqual(r["arms"]["primary"]["consistency_mismatch_runs"], [])

    def test_fail(self):
        p = dict(PASS_PRIMARY, c3b=(30, 5, True))  # a sufficient correction is timely
        self.assertEqual(self.outcome(p)["primary_outcome"], "FAIL")

    def test_fail_exec(self):
        p = dict(PASS_PRIMARY, c3b=(30, 120, True), c4=(20, 100, True))  # sufficient ones too slow to execute
        self.assertEqual(self.outcome(p)["primary_outcome"], "FAIL-EXEC")

    def test_gate_total(self):
        p = dict(PASS_PRIMARY, c1=(70, 2, False), c2=(80, 3, False))  # nothing timely; c3b exec-timely
        self.assertEqual(self.outcome(p)["primary_outcome"], "GATE-TOTAL")

    def test_fail_nosuff(self):
        p = {k: (g, e, False) for k, (g, e, _) in PASS_PRIMARY.items()}
        self.assertEqual(self.outcome(p)["primary_outcome"], "FAIL-NOSUFF")

    def test_void_control_truncates(self):
        bad_control = dict(CONTROL_OK, c1=(5, 2, False))  # control arm truncates too
        r = self.outcome(PASS_PRIMARY, control=bad_control)
        self.assertEqual(r["primary_outcome"], "VOID")
        self.assertTrue(any("anti-truncation" in v for v in r["void_reasons"]))


class TestGuards(Base):
    def test_void_token_override(self):
        def m(x): x["frozen"]["token_lifetime_override"] = True
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_void_token_lifetime_differs(self):
        def m(x): x["runs"][0]["token_exp_ms"] += 600 * S
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_void_hand_set_window(self):
        def m(x): x["frozen"]["window_value_ms_declared"] = 120 * S
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_not_frozen_on_tbd(self):
        def m(x): x["frozen"]["stack"]["idp_version"] = "TBD"
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertEqual(r["status"], "NOT_FROZEN")
        self.assertIsNone(r["primary_outcome"])

    # ---- P0: strict schema bounds
    def test_invalid_q_string(self):
        def m(x): x["frozen"]["window_rule"]["q"] = "TBD"
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "INVALID_MANIFEST")

    def test_invalid_q_out_of_range(self):
        def m(x): x["frozen"]["window_rule"]["q"] = 7
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "INVALID_MANIFEST")

    def test_invalid_nonpositive_poll(self):
        def m(x): x["frozen"]["poll_interval_ms"] = 0
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "INVALID_MANIFEST")

    def test_invalid_log_hash(self):
        def m(x): x["runs"][0]["log_hashes"] = {"gateway": "not-a-hash"}
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "INVALID_MANIFEST")

    # ---- P0: token lifetime cross-file consistency
    def test_not_frozen_lifetime_mismatch(self):
        def m(x):
            x["frozen"]["token_lifetime_default_s"] = 3600
            for r in x["runs"]:
                r["token_exp_ms"] = r["token_issue_ms"] + 3600 * S  # runs consistent with manifest, not with source
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "NOT_FROZEN")

    def test_not_frozen_lifetime_source_mismatch(self):
        def m(x): x["frozen"]["token_lifetime_source"] = "another citation"
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["status"], "NOT_FROZEN")

    # ---- P0: exact counts
    def test_void_extra_run(self):
        def m(x):
            extra = copy.deepcopy([r for r in x["runs"] if r["arm"] == "primary" and r["kind"] == "correction"][0])
            extra["run_id"] = "primary-corr-extra"
            x["runs"].append(extra)
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_void_withheld_run(self):
        def m(x): x["runs"] = [r for r in x["runs"] if r["run_id"] != "primary-base-0"]
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    # ---- P0: timestamp ordering
    def _ordering(self, field, delta_ms, kind="correction"):
        def m(x):
            r = [r for r in x["runs"] if r["arm"] == "primary" and r["kind"] == kind][0]
            r[field] = r["t_jdagger_ms"] + delta_ms if field != "effect_ms" else r["gate_pass_ms"] + delta_ms
        return self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"]

    def test_void_gate_before_alert(self):
        self.assertEqual(self._ordering("gate_pass_ms", -1), "VOID")

    def test_void_effect_before_gate(self):
        self.assertEqual(self._ordering("effect_ms", -1), "VOID")

    def test_void_baseline_x2_before_alert(self):
        self.assertEqual(self._ordering("t_x2_ms", -1, kind="baseline"), "VOID")

    def test_void_evidence_before_event(self):
        def m(x): x["runs"][0]["evidence"][1]["first_readable_ms"] = x["runs"][0]["evidence"][1]["event_ms"] - 1
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    # ---- P1: integrity
    def test_void_duplicate_run_id(self):
        def m(x): x["runs"][1]["run_id"] = x["runs"][0]["run_id"]
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_void_unknown_correction(self):
        def m(x):
            r = [r for r in x["runs"] if r["kind"] == "correction"][0]
            r["correction_id"] = "c9"
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    def test_void_duplicate_evidence(self):
        def m(x): x["runs"][0]["evidence"].append(dict(x["runs"][0]["evidence"][0]))
        self.assertEqual(self.outcome(PASS_PRIMARY, mutate=m)["primary_outcome"], "VOID")

    # ---- cond (iii) semantics diagnostic
    def test_attribution_stable_in_pass(self):
        r = self.outcome(PASS_PRIMARY)
        self.assertEqual(r["arms"]["primary"]["attributing_corrections"], ["c3b", "c4"])
        self.assertTrue(r["arms"]["primary"]["attribution_stable_run_paired"])

    def test_not_frozen_on_registry_change(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        self.cp.write_text(self.cp.read_text() + "\n# edited after freeze\n")
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertEqual(r["status"], "NOT_FROZEN")

    def _shipped(self):
        cp, sp = HERE / "corrections.yaml", HERE / "sources.yaml"
        fc = json.loads((HERE / "frozen_config.json").read_text())
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, cp, sp)
        m["frozen"] = copy.deepcopy(fc)
        return analysis.analyse(m, yaml.safe_load(cp.read_text()), yaml.safe_load(sp.read_text()), cp, sp, SCHEMA, fc)

    @unittest.skipIf(EXPECT_FROZEN, "package is frozen: see test_shipped_package_is_frozen")
    def test_shipped_registry_is_not_frozen(self):
        """Before the verifier build, the only freeze blocker is the missing build record."""
        r = self._shipped()
        self.assertEqual(r["status"], "NOT_FROZEN")
        self.assertEqual(r["freeze_blockers"],
                         ["verifier/BUILD_RECORD.json is missing: run verifier/build_and_lock.sh before deposit"])

    @unittest.skipUnless(EXPECT_FROZEN, "verifier not built yet: see test_shipped_registry_is_not_frozen")
    def test_shipped_package_is_frozen(self):
        """Positive freeze test: valid BUILD_RECORD.json, matching source tree, jar and lock => no blocker."""
        import re
        import subprocess
        vdir = HERE / "verifier"
        rec = json.loads((vdir / "BUILD_RECORD.json").read_text())
        # Triple match, recomputed here independently of freeze_blockers.
        self.assertEqual(analysis.source_tree_sha256(vdir), rec["verifier_source_tree_sha256"])
        sh = subprocess.run(["bash", "-c", "find pom.xml src -type f -print0 | LC_ALL=C sort -z | "
                             "xargs -0 sha256sum | sha256sum | cut -d' ' -f1"],
                            cwd=vdir, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(sh, rec["verifier_source_tree_sha256"])
        self.assertEqual(hashlib.sha256((vdir / "dist" / "eao5-dpop-verifier.jar").read_bytes()).hexdigest(),
                         rec["verifier_jar_sha256"])
        self.assertEqual(hashlib.sha256((vdir / "dependencies.lock").read_bytes()).hexdigest(),
                         rec["verifier_build_lockfile_sha256"])
        self.assertIs(rec["reproducible"], True)
        lock = (vdir / "dependencies.lock").read_text().splitlines()
        self.assertTrue(lock)
        for line in lock:
            self.assertRegex(line, r"^[0-9a-f]{64}  [^/\s]+\.jar$")
        self.assertTrue(any(re.search(r"spring-security-oauth2-resource-server-7\.1\.1\.jar$", l) for l in lock))
        # And the analysis itself finds no blocker.
        r = self._shipped()
        self.assertNotIn("freeze_blockers", r)
        self.assertEqual(r["status"], "ANALYSED")

    def test_shipped_frozen_config(self):
        fc = json.loads((HERE / "frozen_config.json").read_text())
        self.assertEqual((fc["poll_interval_ms"], fc["window_rule"]["q"]), (100, 0.5))
        self.assertEqual((fc["n_baseline_per_arm"], fc["n_oracle_per_correction"], fc["n_correction_per_correction"]),
                         (30, 20, 30))
        self.assertEqual((fc["stack"]["idp_version"], fc["stack"]["gateway_version"], fc["stack"]["queue_version"]),
                         ("26.7.5", "1.38.5", "4.3.6"))

    def test_not_frozen_manifest_differs_from_deposit(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        deposited = copy.deepcopy(m["frozen"])
        m["frozen"]["window_rule"]["q"] = 0.25  # q changed after the runs
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, deposited)
        self.assertEqual(r["status"], "NOT_FROZEN")
        self.assertIn("frozen.window_rule differs from the deposited frozen_config.json", r["freeze_blockers"])

    def test_not_frozen_without_deposit(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, None)
        self.assertIn("frozen_config.json is missing", r["freeze_blockers"])

    def test_not_frozen_thresholds_not_increasing(self):
        corr = yaml.safe_load(self.cp.read_text())
        corr["gate_threshold_chains"] = {"K1": 1, "K2": 2, "K3": 2, "K4": 4}
        self.cp.write_text(yaml.safe_dump(corr))
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        r = analysis.analyse(m, corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertIn("corrections.gate_threshold_chains is not strictly increasing in K", r["freeze_blockers"])

    def test_void_gate_before_threshold(self):
        def m(x):
            for r in x["runs"]:
                if r["arm"] == "primary" and r["correction_id"] == "c4" and r["kind"] == "correction":
                    r["evidence"][6]["first_readable_ms"] = r["gate_pass_ms"] + 1  # E7 chain not yet readable
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertEqual(r["primary_outcome"], "VOID")
        self.assertTrue(any("before m_K=4" in v for v in r["void_reasons"]))

    def test_void_gate_inflated(self):
        def m(x):
            for r in x["runs"]:
                if r["arm"] == "primary" and r["correction_id"] == "c3b" and r["kind"] == "correction":
                    for ev in r["evidence"]:
                        ev["first_readable_ms"] = r["gate_pass_ms"] - 5 * S  # ready 5 s before the gate passed
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertEqual(r["primary_outcome"], "VOID")
        self.assertTrue(any("after m_K=3" in v for v in r["void_reasons"]))

    def test_k1_gate_needs_one_chain(self):
        ev = [{"item": "E1", "event_ms": 0, "first_readable_ms": 10},
              {"item": "E2", "event_ms": 0, "first_readable_ms": 900}]
        self.assertEqual(analysis.gate_ready_ms(ev, [["E1"], ["E2"]], 1), 10)
        self.assertEqual(analysis.gate_ready_ms(ev, [["E1"], ["E2"]], 2), 900)
        self.assertEqual(analysis.tau_acq(ev, [["E1"], ["E2"]], 1), 10)

    def test_serial_chain_readable_only_when_complete(self):
        ev = [{"item": "E4", "event_ms": 0, "first_readable_ms": 100},
              {"item": "E5", "event_ms": 100, "first_readable_ms": 400}]
        self.assertEqual(analysis.gate_ready_ms(ev, [["E4", "E5"]], 1), 400)
        self.assertEqual(analysis.tau_acq(ev, [["E4", "E5"]], 1), 400)

    def test_shipped_token_lifetime_is_keycloak_default(self):
        src = yaml.safe_load((HERE / "sources.yaml").read_text())
        e = [s for s in src["inputs"] if s["parameter"] == "token_lifetime_self_hosted"][0]
        self.assertEqual(e["value"], 300)
        art = HERE / "provenance" / "Constants_26.7.5.java"
        self.assertEqual(hashlib.sha256(art.read_bytes()).hexdigest(), e["provenance"]["artifact_sha256"])
        self.assertIn("DEFAULT_ACCESS_TOKEN_LIFESPAN = 300;", art.read_text())

    def test_not_frozen_undefined_role(self):
        corr = yaml.safe_load(self.cp.read_text())
        corr["corrections"][0]["required_authority"] = "R_ACQUIRED_AT_RUNTIME"
        self.cp.write_text(yaml.safe_dump(corr))
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        r = analysis.analyse(m, corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertEqual(r["status"], "NOT_FROZEN")
        self.assertTrue(any("not a defined role" in x for x in r["freeze_blockers"]))

    def test_not_frozen_gate_rule_tbd(self):
        corr = yaml.safe_load(self.cp.read_text())
        corr["gate_rule"] = "TBD"
        self.cp.write_text(yaml.safe_dump(corr))
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        r = analysis.analyse(m, corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertEqual(r["status"], "NOT_FROZEN")
        self.assertIn("corrections.gate_rule is TBD", r["freeze_blockers"])

    def test_global_block_makes_gate_infinite(self):
        def m(x):
            for r in x["runs"]:
                if r["arm"] == "primary" and r["correction_id"] == "c3b" and r["kind"] == "correction":
                    r["global_block_active"] = True
        p = dict(PASS_PRIMARY, c3b=(30, 5, True))  # would be FAIL, but c3b is globally blocked
        r = self.outcome(p, mutate=m)
        self.assertEqual(r["arms"]["primary"]["corrections"]["c3b"]["timely"], False)


class TestConformance(Base):
    def test_passing_conformance_is_analysed(self):
        r = self.outcome(PASS_PRIMARY)
        self.assertEqual(r["primary_outcome"], "PASS-O5")

    def _ct(self, tid, decision, phase="pre"):
        def m(x):
            for res in x["conformance"][phase]["results"]:
                if res["test_id"] == tid and res["repetition"] == 1:
                    res["decision"] = decision
        return m

    def test_void_dpop_not_enforced(self):
        r = self.outcome(PASS_PRIMARY, mutate=self._ct("CT3", "allow"))  # B's key accepted
        self.assertEqual(r["primary_outcome"], "VOID")
        self.assertTrue(any("CT3 repetition 1 gave allow" in v for v in r["void_reasons"]))

    def test_void_replay_accepted_after_runs(self):
        r = self.outcome(PASS_PRIMARY, mutate=self._ct("CT4", "allow", "post"))
        self.assertEqual(r["primary_outcome"], "VOID")

    def test_void_bearer_blocked_in_primary(self):
        r = self.outcome(PASS_PRIMARY, mutate=self._ct("CT6", "deny"))
        self.assertEqual(r["primary_outcome"], "VOID")

    def test_void_missing_repetition(self):
        def m(x):
            x["conformance"]["pre"]["results"] = [res for res in x["conformance"]["pre"]["results"]
                                                  if not (res["test_id"] == "CT7" and res["repetition"] == 5)]
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertTrue(any("CT7 repetition 5 missing" in v for v in r["void_reasons"]))

    def test_void_artifact_drift(self):
        def m(x): x["conformance"]["post"]["artifact_sha256"]["verifier_jar"] = "b" * 64
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertTrue(any("changed between" in v for v in r["void_reasons"]))

    def test_void_post_before_last_run(self):
        def m(x): x["conformance"]["post"]["performed_ms"] = 2
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertTrue(any("post was not performed after" in v for v in r["void_reasons"]))

    def test_invalid_without_conformance(self):
        def m(x): del x["conformance"]
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertEqual(r["status"], "INVALID_MANIFEST")

    def test_void_deployed_verifier_not_preregistered(self):
        def m(x):
            for ph in ("pre", "post"):
                x["conformance"][ph]["artifact_sha256"]["verifier_jar"] = "c" * 64
        r = self.outcome(PASS_PRIMARY, mutate=m)
        self.assertEqual(r["primary_outcome"], "VOID")
        self.assertTrue(any("verifier_jar differs from the deposited verifier build" in v for v in r["void_reasons"]))

    def test_not_frozen_verifier_source_edited_after_build(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        f = self.cp.parent / "verifier" / "src" / "main" / "java" / "eao5" / "verifier" / "AuthzController.java"
        f.write_text(f.read_text() + "\n// edited after the build\n")
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertIn("verifier source tree differs from BUILD_RECORD.json", r["freeze_blockers"])

    def test_not_frozen_jar_swapped(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        (self.cp.parent / "verifier" / "dist" / "eao5-dpop-verifier.jar").write_bytes(b"other jar")
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertIn("verifier/dist/eao5-dpop-verifier.jar differs from BUILD_RECORD.json", r["freeze_blockers"])

    def test_source_tree_hash_matches_shell_definition(self):
        import subprocess
        vdir = HERE / "verifier"
        sh = subprocess.run(["bash", "-c", "find pom.xml src -type f -print0 | LC_ALL=C sort -z | "
                             "xargs -0 sha256sum | sha256sum | cut -d' ' -f1"],
                            cwd=vdir, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(analysis.source_tree_sha256(vdir), sh)

    def test_not_frozen_conformance_edited(self):
        m = build_manifest({"primary": PASS_PRIMARY, "control": CONTROL_OK, "lever": LEVER_OK}, self.cp, self.sp)
        p = self.cp.parent / "conformance.yaml"
        p.write_text(p.read_text() + "\n# CT4 dropped after deposit\n")
        r = analysis.analyse(m, self.corr, self.src, self.cp, self.sp, SCHEMA, copy.deepcopy(m["frozen"]))
        self.assertIn("conformance.yaml hash differs from frozen.conformance_file_sha256", r["freeze_blockers"])


class TestPrecedence(unittest.TestCase):
    def test_precedence_literal(self):
        self.assertEqual(analysis.PRECEDENCE, ["VOID", "FAIL-NOSUFF", "FAIL-EXEC", "GATE-TOTAL", "PASS-O5", "FAIL"])

    def test_partition_exhaustive(self):
        """Every combination of flags for three corrections yields exactly one non-VOID category."""
        import itertools
        names = ["a", "b", "c"]
        seen = set()
        for bits in itertools.product([False, True], repeat=9):
            t = dict(zip(names, bits[0:3]))
            e = dict(zip(names, bits[3:6]))
            s = dict(zip(names, bits[6:9]))
            if any(t[n] and not e[n] for n in names):
                continue  # timely implies exec-timely (tau_gate >= 0)
            seen.add(analysis.categorize(names, t, e, s))
        self.assertEqual(seen, {"FAIL-NOSUFF", "FAIL-EXEC", "GATE-TOTAL", "PASS-O5", "FAIL"})


if __name__ == "__main__":
    unittest.main()
