#!/usr/bin/env python3
"""EA-O5-EXP-v0.1 deterministic analysis.

Reads a raw run manifest plus the frozen registry files and mechanically derives
the outcome category defined in the EA-O5 Experimental Contract v0.1, section 2.
It makes no modelling decisions: every rule below is fixed in the contract.

The manifest is never modified. Results are written to analysis_output.json.

Usage:
    python3 analysis.py MANIFEST.json [--out analysis_output.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path

import jsonschema
import yaml

HERE = Path(__file__).resolve().parent
INF = math.inf

# Category precedence, literal and frozen (contract section 2). Evaluated top to bottom.
PRECEDENCE = ["VOID", "FAIL-NOSUFF", "FAIL-EXEC", "GATE-TOTAL", "PASS-O5", "FAIL"]

TOKEN_LIFETIME_TOLERANCE_S = 1  # clock granularity of the exp claim


# ---------------------------------------------------------------- helpers

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_sha256(verifier_dir: Path) -> str:
    """sha256 of the sha256sum listing of pom.xml and every file under src/, paths relative to
    verifier/, sorted bytewise. Identical to source_tree_sha256() in verifier/build_and_lock.sh."""
    files = ["pom.xml"] + [p.relative_to(verifier_dir).as_posix()
                           for p in (verifier_dir / "src").rglob("*") if p.is_file()]
    listing = "".join(f"{sha256_file(verifier_dir / f)}  {f}\n" for f in sorted(files, key=str.encode))
    return hashlib.sha256(listing.encode()).hexdigest()


VERIFIER_HASH_KEYS = {  # conformance artifact name -> BUILD_RECORD.json field
    "verifier_source_tree": "verifier_source_tree_sha256",
    "verifier_build_lockfile": "verifier_build_lockfile_sha256",
    "verifier_jar": "verifier_jar_sha256",
}


def verifier_build_record(verifier_dir: Path) -> tuple[dict | None, list[str]]:
    """The deposited verifier build, checked against the deposited files. Returns (record, blockers)."""
    rec_path = verifier_dir / "BUILD_RECORD.json"
    if not rec_path.exists():
        return None, ["verifier/BUILD_RECORD.json is missing: run verifier/build_and_lock.sh before deposit"]
    rec = json.loads(rec_path.read_text())
    b = []
    if source_tree_sha256(verifier_dir) != rec.get("verifier_source_tree_sha256"):
        b.append("verifier source tree differs from BUILD_RECORD.json")
    for rel, key in (("dependencies.lock", "verifier_build_lockfile_sha256"),
                     ("dist/eao5-dpop-verifier.jar", "verifier_jar_sha256")):
        f = verifier_dir / rel
        if not f.exists():
            b.append(f"verifier/{rel} is missing")
        elif sha256_file(f) != rec.get(key):
            b.append(f"verifier/{rel} differs from BUILD_RECORD.json")
    if rec.get("reproducible") is not True:
        b.append("verifier build was not shown to be reproducible")
    return rec, b


def is_tbd(value) -> bool:
    return isinstance(value, str) and value.strip().upper() in {"TBD", ""}


def nearest_rank_quantile(values: list[float], q: float) -> float:
    """Deterministic nearest-rank quantile; no interpolation."""
    if not values:
        raise ValueError("empty sample")
    xs = sorted(values)
    if q <= 0:
        return xs[0]
    k = math.ceil(q * len(xs))
    return xs[min(max(k, 1), len(xs)) - 1]


def median(values: list[float]) -> float:
    # statistics.median handles inf: (x + inf) / 2 == inf
    return statistics.median(values)


def tau_acq(evidence: list[dict], footprint: list[list[str]], m: int | None = None) -> float:
    """Evidence acquisition time under the frozen gate rule (contract sections 4 and 4a).
    A chain's duration is the sum of d(e) along it; the gate needs m complete chains, so
    tau_acq is the m-th smallest chain duration (m = len(footprint) gives the full footprint)."""
    d = {}
    for ev in evidence:
        fr = ev["first_readable_ms"]
        d[ev["item"]] = INF if fr is None else fr - ev["event_ms"]
    sums = sorted(sum(d.get(item, INF) for item in chain) for chain in footprint)
    m = len(footprint) if m is None else m
    return sums[m - 1]


def gate_ready_ms(evidence: list[dict], footprint: list[list[str]], m: int) -> float:
    """Absolute time at which m chains of the footprint are completely readable.
    A chain is readable when every item in it is readable."""
    fr = {ev["item"]: (INF if ev["first_readable_ms"] is None else ev["first_readable_ms"]) for ev in evidence}
    ready = sorted(max(fr.get(item, INF) for item in chain) for chain in footprint)
    return ready[m - 1]


# ---------------------------------------------------------------- freeze check

def freeze_blockers(manifest: dict, corrections: dict, sources: dict,
                    corrections_path: Path, sources_path: Path,
                    frozen_config: dict | None = None) -> list[str]:
    """Anything listed here means the package is not frozen; no outcome is computed.
    Numeric frozen fields are bounded by the schema; strings are checked for TBD here."""
    b = []
    fz = manifest["frozen"]
    # The manifest's frozen block must equal the deposited frozen_config.json, field by field,
    # so no frozen value (poll interval, q, run counts, stack) can be set after the runs.
    if frozen_config is None:
        b.append("frozen_config.json is missing")
    else:
        # window_value_ms_declared is not known before the runs; it is checked against the rule instead.
        for k in sorted((set(fz) | set(frozen_config)) - {"window_value_ms_declared"}):
            if fz.get(k) != frozen_config.get(k):
                b.append(f"frozen.{k} differs from the deposited frozen_config.json")
    for k, v in fz["stack"].items():
        if is_tbd(v):
            b.append(f"frozen.stack.{k} is TBD")
    if is_tbd(fz["token_lifetime_source"]):
        b.append("frozen.token_lifetime_source is TBD")

    # Cross-file check: the manifest's token lifetime must be the sourced value (P0).
    lt = [s for s in sources["inputs"] if s["parameter"] == "token_lifetime_self_hosted"]
    if len(lt) != 1:
        b.append("sources.yaml must contain exactly one token_lifetime_self_hosted entry")
    else:
        e = lt[0]
        try:
            sourced_value = int(e.get("value"))
        except (TypeError, ValueError):
            sourced_value = None
        if sourced_value != fz["token_lifetime_default_s"]:
            b.append("frozen.token_lifetime_default_s differs from sources.yaml token_lifetime_self_hosted.value")
        if str(e.get("source")) != fz["token_lifetime_source"]:
            b.append("frozen.token_lifetime_source differs from sources.yaml token_lifetime_self_hosted.source")
        prov = e.get("provenance") or {}
        for k in ("software_version", "documentation_version", "access_date", "exact_statement", "artifact_sha256"):
            if is_tbd(str(prov.get(k, ""))):
                b.append(f"sources.token_lifetime_self_hosted.provenance.{k} is TBD")
        if is_tbd(str(e.get("realm_rule", ""))):
            b.append("sources.token_lifetime_self_hosted.realm_rule is TBD")

    # Authority policy: checked, not acquired; roles separate from K.
    if is_tbd(str(corrections.get("authority_rule", ""))):
        b.append("corrections.authority_rule is TBD")
    roles = corrections.get("authority_roles") or {}
    if not isinstance(roles, dict) or not roles:
        b.append("corrections.authority_roles is empty")
        roles = {}
    for r, sem in roles.items():
        if is_tbd(str(sem)):
            b.append(f"corrections.authority_roles.{r} has no written semantics")
    if is_tbd(str(corrections.get("gate_rule", ""))):
        b.append("corrections.gate_rule is TBD")
    # Class-conditioned thresholds: number of complete footprint chains, strictly increasing in K.
    thr = corrections.get("gate_threshold_chains")
    k_order = corrections.get("k_order", [])
    if not isinstance(thr, dict) or set(thr) != set(k_order):
        b.append("corrections.gate_threshold_chains must give m_K for every class in k_order")
    else:
        ms = [thr[k] for k in k_order]
        if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 1 for x in ms):
            b.append("corrections.gate_threshold_chains values must be integers >= 1")
        elif any(a >= c for a, c in zip(ms, ms[1:])):
            b.append("corrections.gate_threshold_chains is not strictly increasing in K")
        else:
            for c in corrections["corrections"]:
                if thr[c["K_class"]] > len(c["footprint"]):
                    b.append(f"corrections.{c['id']}: m_{c['K_class']} exceeds the number of footprint chains")
    for c in corrections["corrections"]:
        ra = c.get("required_authority")
        if is_tbd(ra):
            b.append(f"corrections.{c['id']}.required_authority is TBD")
        elif ra not in roles:
            b.append(f"corrections.{c['id']}.required_authority {ra} is not a defined role")
    for s in sources["inputs"]:
        if s["scope"] == "primary" and s["measured_or_imposed"] == "imposed":
            if is_tbd(s.get("source")) or is_tbd(str(s.get("value"))):
                b.append(f"sources.{s['parameter']}: primary imposed input without source/value")
    if sha256_file(corrections_path) != fz["corrections_file_sha256"]:
        b.append("corrections.yaml hash differs from frozen.corrections_file_sha256")
    if sha256_file(sources_path) != fz["sources_file_sha256"]:
        b.append("sources.yaml hash differs from frozen.sources_file_sha256")
    b += verifier_build_record(corrections_path.parent / "verifier")[1]
    conf_path = corrections_path.parent / "conformance.yaml"
    if not conf_path.exists():
        b.append("conformance.yaml is missing")
    elif sha256_file(conf_path) != fz["conformance_file_sha256"]:
        b.append("conformance.yaml hash differs from frozen.conformance_file_sha256")
    return b


# ---------------------------------------------------------------- run validity

def conformance_violations(manifest: dict, conformance: dict, build_record: dict | None = None) -> list[str]:
    """Token-path conformance (conformance.yaml). Every violation makes the study VOID:
    without it the control arm is not known to enforce DPoP, nor the primary arm to accept bearer use."""
    v = []
    block = manifest["conformance"]
    reps = conformance["repetitions"]
    expected = {t["id"]: t["expected"] for t in conformance["tests"]}
    wanted_artifacts = set(conformance["artifacts_hashed"])
    for phase in ("pre", "post"):
        ph = block[phase]
        if set(ph["artifact_sha256"]) != wanted_artifacts:
            v.append(f"conformance.{phase}: artifact hashes do not cover exactly {sorted(wanted_artifacts)}")
        seen = {}
        for r in ph["results"]:
            key = (r["test_id"], r["repetition"])
            if key in seen:
                v.append(f"conformance.{phase}: duplicate result {key}")
            seen[key] = r["decision"]
        for tid, exp in expected.items():
            for i in range(1, reps + 1):
                got = seen.get((tid, i))
                if got is None:
                    v.append(f"conformance.{phase}: {tid} repetition {i} missing")
                elif got != exp:
                    v.append(f"conformance.{phase}: {tid} repetition {i} gave {got}, expected {exp}")
        extra = {k for k in seen if k[0] not in expected or not 1 <= k[1] <= reps}
        if extra:
            v.append(f"conformance.{phase}: unregistered results {sorted(extra)}")
    if block["pre"]["artifact_sha256"] != block["post"]["artifact_sha256"]:
        v.append("conformance: artifact hashes changed between the pre-run and post-run tests")
    # The deployed verifier must be the pre-registered one.
    if build_record is not None:
        for phase in ("pre", "post"):
            for art, key in VERIFIER_HASH_KEYS.items():
                if block[phase]["artifact_sha256"].get(art) != build_record.get(key):
                    v.append(f"conformance.{phase}: {art} differs from the deposited verifier build")
    runs = manifest["runs"]
    if runs:
        if block["pre"]["performed_ms"] >= min(r["token_issue_ms"] for r in runs):
            v.append("conformance.pre was not performed before the first run")
        if block["post"]["performed_ms"] <= max(r["t_jdagger_ms"] for r in runs):
            v.append("conformance.post was not performed after the last run")
    return v


def integrity_violations(runs: list[dict], corrections: list[dict]) -> list[str]:
    """Manifest integrity and timestamp ordering. Every violation makes the study VOID."""
    v = []
    allowed = {c["id"]: set(c["arms"]) for c in corrections}
    seen_ids = set()
    for r in runs:
        rid = r["run_id"]
        if rid in seen_ids:
            v.append(f"duplicate run_id {rid}")
        seen_ids.add(rid)

        cid = r.get("correction_id")
        if r["kind"] == "baseline":
            if cid is not None:
                v.append(f"run {rid}: baseline run carries correction_id")
            if r.get("t_x2_ms") is None:
                v.append(f"run {rid}: baseline run without t_x2_ms")
            elif r["t_x2_ms"] <= r["t_jdagger_ms"]:
                v.append(f"run {rid}: t_x2 not after t_jdagger")
        else:
            if cid not in allowed:
                v.append(f"run {rid}: unknown correction_id {cid!r}")
            elif r["arm"] not in allowed[cid]:
                v.append(f"run {rid}: correction {cid} not registered for arm {r['arm']}")
        if r["kind"] == "oracle" and not isinstance(r.get("oracle_prevents_x2"), bool):
            v.append(f"run {rid}: oracle run without boolean oracle_prevents_x2")

        if r["token_exp_ms"] <= r["token_issue_ms"]:
            v.append(f"run {rid}: token exp not after issue")
        gp, ex, ef = r.get("gate_pass_ms"), r.get("execution_start_ms"), r.get("effect_ms")
        if gp is not None and gp < r["t_jdagger_ms"]:
            v.append(f"run {rid}: gate passed before t_jdagger")
        if ex is not None and (gp is None or ex < gp):
            v.append(f"run {rid}: execution started before gate pass")
        if ef is not None and (gp is None or ef < gp or (ex is not None and ef < ex)):
            v.append(f"run {rid}: effect before gate pass or execution start")

        items = [e["item"] for e in r["evidence"]]
        dups = sorted({i for i in items if items.count(i) > 1})
        if dups:
            v.append(f"run {rid}: duplicate evidence items {dups}")
        for e in r["evidence"]:
            if e["first_readable_ms"] is not None and e["first_readable_ms"] < e["event_ms"]:
                v.append(f"run {rid}: {e['item']} readable before its event")
    return v


def count_violations(runs: list[dict], corrections: list[dict], fz: dict) -> list[str]:
    """Exact pre-registered counts: no run may be added or withheld."""
    v = []
    nb, no, nc = fz["n_baseline_per_arm"], fz["n_oracle_per_correction"], fz["n_correction_per_correction"]
    for arm in ("primary", "control", "lever"):
        k = sum(1 for r in runs if r["arm"] == arm and r["kind"] == "baseline")
        if k != nb:
            v.append(f"{arm}: {k} baseline runs, frozen count is {nb}")
        for c in corrections:
            if arm not in c["arms"]:
                continue
            for kind, n in (("oracle", no), ("correction", nc)):
                k = sum(1 for r in runs if r["arm"] == arm and r["kind"] == kind and r.get("correction_id") == c["id"])
                if k != n:
                    v.append(f"{arm}/{c['id']}: {k} {kind} runs, frozen count is {n}")
    return v


# ---------------------------------------------------------------- core logic

def categorize(names: list[str], timely: dict, exec_timely: dict, suff: dict) -> str:
    """Literal precedence (contract section 2), VOID handled by the caller."""
    C_timely = {c for c in names if timely[c]}
    C_suff = {c for c in names if suff[c]}
    cond_iii = any(exec_timely[c] and not timely[c] for c in C_suff)

    if not C_suff:
        return "FAIL-NOSUFF"
    if not any(exec_timely[c] for c in C_suff):
        return "FAIL-EXEC"
    if cond_iii and not C_timely:
        return "GATE-TOTAL"
    if C_timely and not (C_timely & C_suff) and cond_iii:
        return "PASS-O5"
    return "FAIL"


def analyse_arm(arm: str, runs: list[dict], corrections: list[dict], q: float,
                thresholds: dict, poll_ms: int) -> dict:
    void = []
    arm_runs = [r for r in runs if r["arm"] == arm]
    baseline = [r for r in arm_runs if r["kind"] == "baseline"]
    if not baseline:
        return {"void_reasons": [f"{arm}: no baseline runs"], "category_raw": None}
    windows = []
    for r in baseline:
        if r.get("t_x2_ms") is None:
            void.append(f"{arm}: baseline run {r['run_id']} has no X2; window undefined")
        else:
            windows.append(r["t_x2_ms"] - r["t_jdagger_ms"])
    if not windows:
        return {"void_reasons": void, "category_raw": None}
    W = nearest_rank_quantile(windows, q)

    names = [c["id"] for c in corrections if arm in c["arms"]]
    per = {}
    for c in corrections:
        if c["id"] not in names:
            continue
        cid = c["id"]
        oracle = [r for r in arm_runs if r["kind"] == "oracle" and r.get("correction_id") == cid]
        corr = [r for r in arm_runs if r["kind"] == "correction" and r.get("correction_id") == cid]
        if not oracle:
            void.append(f"{arm}: no oracle runs for {cid}")
        if not corr:
            void.append(f"{arm}: no correction runs for {cid}")
        if not oracle or not corr:
            continue
        S = all(r.get("oracle_prevents_x2") is True for r in oracle)
        g_list, e_list, tot_list, acq_list = [], [], [], []
        for r in corr:
            blocked = c["global_block_applicable"] and r.get("global_block_active", False)
            gp = r.get("gate_pass_ms")
            g = INF if (blocked or gp is None) else gp - r["t_jdagger_ms"]
            eff = r.get("effect_ms")
            e = INF if (g == INF or eff is None) else eff - gp
            g_list.append(g)
            e_list.append(e)
            tot_list.append(g + e)
            m = thresholds[c["K_class"]]
            acq_list.append(tau_acq(r["evidence"], c["footprint"], m))
            # Gate-rule compliance: gate_pass at the earliest poll at which m chains are readable.
            # Earlier = the rule was bypassed; later than one poll interval = gate time was inflated.
            if not blocked and gp is not None:
                ready = gate_ready_ms(r["evidence"], c["footprint"], m)
                if gp < ready:
                    void.append(f"{arm}: run {r['run_id']} gate passed before m_K={m} chains were readable")
                elif gp - ready > poll_ms:
                    void.append(f"{arm}: run {r['run_id']} gate passed {gp - ready} ms after m_K={m} chains "
                                f"were readable (> one poll interval, {poll_ms} ms)")
        tg, te, tt, ta = median(g_list), median(e_list), median(tot_list), median(acq_list)
        # Run-paired diagnostic for (iii): share of runs where execution fits but gate + execution does not.
        paired = sum(1 for e, t in zip(e_list, tot_list) if e <= W and t > W) / len(corr)
        per[cid] = {
            "K_class": c["K_class"],
            "tau_acq_ms": ta, "tau_gate_ms": tg, "tau_exec_ms": te, "tau_tot_ms": tt,
            "timely": tt <= W, "exec_timely": te <= W, "sufficient": S,
            "aggregate_iii": S and te <= W and not tt <= W,
            "paired_iii_share": paired, "paired_iii": paired > 0.5,
            "n_oracle": len(oracle), "n_correction": len(corr),
            "gate_before_evidence_warning": tg < ta,
        }

    if void:
        return {"W_ms": W, "corrections": per, "void_reasons": void, "category_raw": None}

    cat = categorize(names,
                     {c: per[c]["timely"] for c in names},
                     {c: per[c]["exec_timely"] for c in names},
                     {c: per[c]["sufficient"] for c in names})

    # Consistency report (does not change the category): predicted prevention vs observed X2.
    mismatches = []
    for r in arm_runs:
        if r["kind"] != "correction":
            continue
        cid = r["correction_id"]
        predicted_prevented = per[cid]["timely"] and per[cid]["sufficient"]
        if predicted_prevented == r["x2_observed"]:
            mismatches.append(r["run_id"])
    # Attribution stability (diagnostic, never changes the category): when the aggregate
    # rule attributes the outcome to the gate, does the run-paired rule agree for at least
    # one of the attributing corrections?
    attributing = [c for c in names if per[c]["aggregate_iii"]]
    stable = None
    if cat in ("PASS-O5", "GATE-TOTAL"):
        stable = any(per[c]["paired_iii"] for c in attributing)
    return {
        "W_ms": W,
        "attributing_corrections": attributing,
        "attribution_stable_run_paired": stable,
        "C_timely": sorted(c for c in names if per[c]["timely"]),
        "C_suff": sorted(c for c in names if per[c]["sufficient"]),
        "corrections": per,
        "category_raw": cat,
        "consistency_mismatch_runs": mismatches,
        "void_reasons": [],
    }


def analyse(manifest: dict, corrections: dict, sources: dict,
            corrections_path: Path, sources_path: Path, schema: dict,
            frozen_config: dict | None = None) -> dict:
    out = {"precedence": PRECEDENCE}
    try:
        jsonschema.validate(manifest, schema)
    except jsonschema.ValidationError as exc:
        path = "/".join(str(p) for p in exc.absolute_path)
        out.update({"status": "INVALID_MANIFEST", "schema_error": f"{path}: {exc.message}",
                    "primary_outcome": None})
        return out
    out.update({"contract_version": manifest["contract_version"], "study_id": manifest["study_id"]})

    blockers = freeze_blockers(manifest, corrections, sources, corrections_path, sources_path, frozen_config)
    if blockers:
        out.update({"status": "NOT_FROZEN", "freeze_blockers": blockers, "primary_outcome": None})
        return out

    fz = manifest["frozen"]
    runs = manifest["runs"]
    void = []

    # Kill and validity checks (contract section 7).
    if fz["token_lifetime_override"]:
        void.append("token_lifetime_override is true")
    default_s = fz["token_lifetime_default_s"]
    for r in runs:
        life_s = (r["token_exp_ms"] - r["token_issue_ms"]) / 1000.0
        if abs(life_s - default_s) > TOKEN_LIFETIME_TOLERANCE_S:
            void.append(f"run {r['run_id']}: token lifetime {life_s:.0f}s differs from frozen default {default_s}s")
    void += integrity_violations(runs, corrections["corrections"])
    void += conformance_violations(manifest, yaml.safe_load((corrections_path.parent / "conformance.yaml").read_text()),
                                   verifier_build_record(corrections_path.parent / "verifier")[0])
    void += count_violations(runs, corrections["corrections"], fz)

    q = float(fz["window_rule"]["q"])
    arms = {a: analyse_arm(a, runs, corrections["corrections"], q,
                           corrections["gate_threshold_chains"], fz["poll_interval_ms"])
            for a in ("primary", "control", "lever")}

    declared = fz.get("window_value_ms_declared")
    if declared is not None and arms["primary"].get("W_ms") is not None and declared != arms["primary"]["W_ms"]:
        void.append("declared window differs from the window computed by the frozen rule")

    void += arms["primary"]["void_reasons"] + arms["control"]["void_reasons"]
    if arms["control"]["category_raw"] not in (None, "FAIL"):
        void.append(f"control arm category is {arms['control']['category_raw']}, not FAIL (anti-truncation control failed)")

    primary = "VOID" if void else arms["primary"]["category_raw"]
    out.update({
        "status": "ANALYSED",
        "primary_outcome": primary,
        "void_reasons": void,
        "arms": arms,
        "lever_arm_note": "secondary; reported only, never changes the primary outcome",
    })
    return out


def _json_default(x):
    if isinstance(x, float) and math.isinf(x):
        return "inf"
    raise TypeError(type(x))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--corrections", default=str(HERE / "corrections.yaml"))
    ap.add_argument("--sources", default=str(HERE / "sources.yaml"))
    ap.add_argument("--schema", default=str(HERE / "MANIFEST_SCHEMA.json"))
    ap.add_argument("--frozen-config", default=str(HERE / "frozen_config.json"))
    ap.add_argument("--out", default="analysis_output.json")
    a = ap.parse_args(argv)

    cp, sp, fp = Path(a.corrections), Path(a.sources), Path(a.frozen_config)
    manifest = json.loads(Path(a.manifest).read_text())
    result = analyse(manifest, yaml.safe_load(cp.read_text()), yaml.safe_load(sp.read_text()),
                     cp, sp, json.loads(Path(a.schema).read_text()),
                     json.loads(fp.read_text()) if fp.exists() else None)
    result["inputs_sha256"] = {
        "manifest": sha256_file(Path(a.manifest)),
        "analysis.py": sha256_file(Path(__file__)),
        "corrections.yaml": sha256_file(cp),
        "sources.yaml": sha256_file(sp),
        "frozen_config.json": sha256_file(fp) if fp.exists() else None,
    }
    text = json.dumps(result, indent=2, default=_json_default)
    text = text.replace("Infinity", '"inf"')
    Path(a.out).write_text(text)
    print(result["status"], result.get("primary_outcome"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
