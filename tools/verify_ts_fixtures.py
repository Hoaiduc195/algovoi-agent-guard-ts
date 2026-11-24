"""Reverse interop: the PYTHON reference verifies a bundle TYPESCRIPT produced.

Run: PYTHONPATH=<python-repo>/src python verify_ts_fixtures.py <ts_fixtures.json>
Exits non-zero on any refusal that should have passed (or vice versa).
"""
import json
import sys

from algovoi_agent_guard import keys, l1, mandate, intent as im, guard, verify


def main(path):
    b = json.load(open(path, encoding="utf-8"))
    now = __import__("datetime").datetime.fromisoformat(b["now"].replace("Z", "+00:00"))
    checks = []

    ok, reasons = mandate.verify_mandate(b["envelope"], now)
    checks.append(("mandate valid", ok, reasons))

    checks.append(("mandate_ref recomputes",
                   l1.mandate_ref(b["envelope"]["payer"], b["envelope"]["cap"],
                                  b["envelope"]["period"], b["envelope"]["revocation_state"])
                   == b["envelope"]["mandate_ref"], []))

    checks.append(("Ed25519 envelope sig (TS->Py)",
                   keys.verify(b["human_pub"],
                               __import__("algovoi_agent_guard.jcs", fromlist=["canonicalise"]).canonicalise(
                                   mandate.mandate_body(b["envelope"])),
                               b["envelope"]["sig"]), []))

    ok, reasons = im.verify_approval(b["approval_allow"], b["allow_ref"],
                                     b["intent_allow"], b["human_pub"], now)
    checks.append(("countersign valid", ok, reasons))

    ok, reasons = verify.verify_decision(b["envelope"], b["receipt_allow"], b["ledger_snapshot"])
    checks.append(("ALLOW receipt verifies", ok, reasons))

    ok, reasons = verify.verify_decision(b["envelope"], b["receipt_deny"], b["ledger_snapshot"])
    checks.append(("DENY receipt verifies", ok, reasons))

    ok, reasons = verify.verify_settlement(b["envelope"], b["receipt_allow"],
                                           b["settlement"], b["ledger_snapshot"])
    checks.append(("settlement verifies", ok, reasons))

    ok, reasons = mandate.verify_mandate(b["revoked_envelope"], now)
    checks.append(("revoked refused", not ok and any("revoked" in r for r in reasons), reasons))

    failed = 0
    for name, ok, reasons in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {reasons}"))
        if not ok:
            failed += 1
    print(f"\n{len(checks) - failed}/{len(checks)} reverse-interop checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(sys.argv[1])
