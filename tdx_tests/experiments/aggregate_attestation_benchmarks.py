#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import platform
import socket
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


STAGES = [
    "context_create",
    "init_quote_size_query",
    "init_quote_full",
    "quote_size_query",
    "report_generation",
    "quote_generation",
    "collateral_fetch",
    "verification",
    "end_to_end",
]


def percentile(values: list[int], ratio: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(ratio * len(ordered)) - 1))
    return ordered[index]


def stats(values: list[int]) -> dict[str, object]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "p95": None,
            "stdev": None,
            "values": [],
        }
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "values": values,
    }


def load_cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return ""
    for line in cpuinfo.read_text().splitlines():
        if line.lower().startswith("model name"):
            _, value = line.split(":", 1)
            return value.strip()
    return ""


def summarize_scenario(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text())
    scenario = payload["scenario"]
    raw_samples = payload["samples"]
    measured = [s for s in raw_samples if not s["warmup"]]
    successful = [s for s in measured if s["success"]]
    failure_stage_counts = Counter(
        s["failure_stage"] for s in measured if not s["success"] and s["failure_stage"]
    )
    qv_results = Counter(s["qv_result"] for s in measured)
    qv_ret_codes = Counter(str(s["qv_ret"]) for s in measured)
    quote_versions = Counter(str(s["quote_version"]) for s in measured if s["quote_version"])
    att_key_types = Counter(str(s["att_key_type"]) for s in measured if s["att_key_type"])

    per_stage_ns: dict[str, dict[str, object]] = {}
    per_stage_cycles: dict[str, dict[str, object]] = {}
    for stage in STAGES:
        ns_values = [
            s["stages"][stage]["nanoseconds"]
            for s in successful
            if s["stages"][stage]["present"]
        ]
        cycle_values = [
            s["stages"][stage]["cycles"]
            for s in successful
            if s["stages"][stage]["present"]
        ]
        per_stage_ns[stage] = stats(ns_values)
        per_stage_cycles[stage] = stats(cycle_values)

    quote_sizes = [s["quote_size"] for s in successful if s["quote_size"]]
    collateral_sizes = [s["collateral_size"] for s in successful if s["collateral_size"]]
    warmup_samples = [s for s in raw_samples if s["warmup"]]
    first_warmup = warmup_samples[0] if warmup_samples else None

    quote_gen_stats = per_stage_ns["quote_generation"]
    collateral_fetch_stats = per_stage_ns["collateral_fetch"]
    variability = {
        "quote_generation_cv": (
            (quote_gen_stats["stdev"] / quote_gen_stats["mean"])
            if quote_gen_stats["count"] and quote_gen_stats["mean"]
            else None
        ),
        "quote_generation_p95_over_p50": (
            (quote_gen_stats["p95"] / quote_gen_stats["median"])
            if quote_gen_stats["count"] and quote_gen_stats["median"]
            else None
        ),
        "collateral_fetch_cv": (
            (collateral_fetch_stats["stdev"] / collateral_fetch_stats["mean"])
            if collateral_fetch_stats["count"] and collateral_fetch_stats["mean"]
            else None
        ),
        "collateral_fetch_p95_over_p50": (
            (collateral_fetch_stats["p95"] / collateral_fetch_stats["median"])
            if collateral_fetch_stats["count"] and collateral_fetch_stats["median"]
            else None
        ),
    }

    end_to_end_mean = per_stage_ns["end_to_end"]["mean"]
    stage_share_of_end_to_end = {}
    if end_to_end_mean:
        for stage in STAGES:
            if stage == "end_to_end":
                continue
            stage_mean = per_stage_ns[stage]["mean"]
            if stage_mean:
                stage_share_of_end_to_end[stage] = stage_mean / end_to_end_mean

    return {
        "scenario": scenario,
        "setup_error": payload.get("setup_error", ""),
        "raw_file": str(path),
        "reliability": {
            "attempted_measured_iterations": len(measured),
            "successful_measured_iterations": len(successful),
            "failed_measured_iterations": len(measured) - len(successful),
            "success_rate": (len(successful) / len(measured)) if measured else 0.0,
            "failure_stage_counts": dict(failure_stage_counts),
        },
        "dimensions": {
            "quote_size_bytes": stats(quote_sizes),
            "collateral_size_bytes": stats(collateral_sizes),
        },
        "latency_nanoseconds": per_stage_ns,
        "cycles": per_stage_cycles,
        "stage_share_of_end_to_end": stage_share_of_end_to_end,
        "variability": variability,
        "verification_outputs": {
            "qv_results": dict(qv_results),
            "qv_ret_codes": dict(qv_ret_codes),
            "quote_versions": dict(quote_versions),
            "att_key_types": dict(att_key_types),
        },
        "cold_start_reference": first_warmup,
    }


def main() -> int:
    if len(sys.argv) < 3:
        print(
            f"usage: {sys.argv[0]} <output-json> <scenario-json> [<scenario-json> ...]",
            file=sys.stderr,
        )
        return 2

    output_path = Path(sys.argv[1])
    scenario_paths = [Path(arg) for arg in sys.argv[2:]]
    scenarios = [summarize_scenario(path) for path in scenario_paths]

    baseline_by_path = {}
    for scenario in scenarios:
        key = scenario["scenario"]["path_mode"]
        if scenario["scenario"]["algorithm"] == "ecdsa_p256":
            baseline_by_path[key] = scenario

    comparisons: dict[str, object] = {
        "quote_size_expansion_vs_ecdsa": {},
        "collateral_size_expansion_vs_ecdsa": {},
        "latency_ratio_vs_ecdsa": {},
    }

    ratio_stages = ["quote_generation", "collateral_fetch", "verification", "end_to_end"]
    for scenario in scenarios:
        path_mode = scenario["scenario"]["path_mode"]
        baseline = baseline_by_path.get(path_mode)
        scenario_key = f"{path_mode}:{scenario['scenario']['algorithm']}"
        if baseline is None:
            continue
        if scenario["scenario"]["algorithm"] == "ecdsa_p256":
            continue

        base_quote_mean = baseline["dimensions"]["quote_size_bytes"]["mean"]
        sc_quote_mean = scenario["dimensions"]["quote_size_bytes"]["mean"]
        if base_quote_mean and sc_quote_mean:
            comparisons["quote_size_expansion_vs_ecdsa"][scenario_key] = sc_quote_mean / base_quote_mean

        base_coll_mean = baseline["dimensions"]["collateral_size_bytes"]["mean"]
        sc_coll_mean = scenario["dimensions"]["collateral_size_bytes"]["mean"]
        if base_coll_mean and sc_coll_mean:
            comparisons["collateral_size_expansion_vs_ecdsa"][scenario_key] = sc_coll_mean / base_coll_mean

        for stage in ratio_stages:
            base_mean = baseline["latency_nanoseconds"][stage]["mean"]
            sc_mean = scenario["latency_nanoseconds"][stage]["mean"]
            if base_mean and sc_mean:
                comparisons["latency_ratio_vs_ecdsa"].setdefault(stage, {})[scenario_key] = sc_mean / base_mean

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "cpu_model": load_cpu_model(),
            "sgx_mode": os.environ.get("BENCH_ENV_SGX_MODE", ""),
            "tdx_guest_device": os.environ.get("BENCH_ENV_TDX_GUEST_DEVICE", ""),
            "ecdsa_quote_transport_port": os.environ.get("BENCH_ENV_ECDSA_PORT", ""),
            "mldsa_quote_transport_port": os.environ.get("BENCH_ENV_MLDSA_PORT", ""),
            "mldsa_verifier_mode": os.environ.get("BENCH_ENV_MLDSA_VERIFIER_MODE", ""),
            "ecdsa_verifier_mode": os.environ.get("BENCH_ENV_ECDSA_VERIFIER_MODE", ""),
            "measured_iterations": os.environ.get("BENCH_ENV_ITERATIONS", ""),
            "warmup_iterations": os.environ.get("BENCH_ENV_WARMUP", ""),
        },
        "scenarios": scenarios,
        "comparisons": comparisons,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))
    print(f"[aggregate] wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
