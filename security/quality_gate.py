"""
Security quality gate.

Aggregates all scanner reports and exits with code 1 when the number of
findings at any severity exceeds the limits in thresholds.json.

usage: python security/quality_gate.py [--reports reports] [--thresholds security/thresholds.json]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import SEVERITIES, TOOLS, collect, count_by_severity, evaluate_gate  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--thresholds", default=str(Path(__file__).parent / "thresholds.json"))
    args = ap.parse_args()

    thresholds = json.loads(Path(args.thresholds).read_text())
    findings, status = collect(args.reports)
    counts = count_by_severity(findings)
    passed, violations = evaluate_gate(findings, thresholds)

    print("=" * 60)
    print(" SECURITY QUALITY GATE")
    print("=" * 60)
    print(f"{'Tool':<12}{'Status':<10}" + "".join(f"{s[:4]:>6}" for s in SEVERITIES))
    for tool in TOOLS:
        tc = count_by_severity([f for f in findings if f["tool"] == tool])
        print(f"{tool:<12}{status[tool]:<10}" + "".join(f"{tc[s]:>6}" for s in SEVERITIES))
    print("-" * 60)
    print(f"{'TOTAL':<22}" + "".join(f"{counts[s]:>6}" for s in SEVERITIES))
    print()

    missing = [t for t, s in status.items() if s == "missing"]
    if missing:
        print(f"WARNING: no report found for: {', '.join(missing)}")

    if passed:
        print("RESULT: PASSED - no severity threshold exceeded")
    else:
        print("RESULT: FAILED")
        for v in violations:
            print(f"  - {v}")
        print("\nTop blocking findings:")
        blocking = [f for f in findings if thresholds.get(f["severity"]) is not None]
        for f in blocking[:15]:
            print(f"  [{f['severity']}] {f['tool']}: {f['title']} ({f['location']})")

    Path(args.reports, "gate-result.json").write_text(json.dumps(
        {"passed": passed, "violations": violations, "counts": counts, "thresholds": thresholds},
        indent=2,
    ))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
