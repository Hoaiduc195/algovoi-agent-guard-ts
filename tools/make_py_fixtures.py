"""Emit a deterministic cross-language fixture bundle from the PYTHON reference.

The TypeScript interop test verifies every component offline; the reverse
direction (TS produces, Python verifies) uses the same fixed key and instant.
Run: PYTHONPATH=<python-repo>/src python make_py_fixtures.py <out.json>
"""
import base64
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from algovoi_agent_guard import keys, l1, mandate, intent as im, guard, receipt, ledger, verify

PRIV = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
NOW = datetime(2026, 11, 24, 3, 0, 0, tzinfo=timezone.utc)
EXPIRES = (NOW + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(out):
    pub = keys.pub_from_priv(PRIV)
    env = mandate.issue_mandate(
        payer="0x00000000000000000000000000000000DEADBEEF", cap="1000",
        human_priv=PRIV, period="monthly", payee="*", max_per_charge="600", now=NOW,
    )
    agent_ref = l1.ref({"type": "agent", "id": "demo-agent"})
    policy_ref = guard.policy_bound_ref(env)
    allow_ref = l1.guardrail_ref(agent_ref, env["mandate_ref"], policy_ref, "ALLOW")

    i1 = im.make_intent(charge_id="charge-001", mandate_ref=env["mandate_ref"],
                        payee="merchant-a", amount=400, asset="USDC", at=NOW)
    a1 = im.approve(allow_ref, i1, PRIV, EXPIRES)

    with tempfile.TemporaryDirectory() as td:
        led = ledger.Ledger(td + "/ledger.jsonl")
        g = guard.Guard(env, led, agent_ref, now_fn=lambda: NOW)
        r_allow = g.decide(i1, a1)
        snap = led.snapshot()

        # A DENY: amount 700 exceeds max_per_charge 600 (countersign valid).
        i2 = im.make_intent(charge_id="charge-002", mandate_ref=env["mandate_ref"],
                            payee="merchant-a", amount=700, asset="USDC", at=NOW)
        allow_ref2 = l1.guardrail_ref(agent_ref, env["mandate_ref"], policy_ref, "ALLOW")
        a2 = im.approve(allow_ref2, i2, PRIV, EXPIRES)
        r_deny = g.decide(i2, a2)

    settlement = receipt.bind_settlement(r_allow, "tx:0xabc123")
    revoked = mandate.revoke(env, PRIV)

    # Sanity: the Python reference verifies its own bundle.
    assert verify.verify_decision(env, r_allow, snap)[0], "py self-verify ALLOW failed"
    assert verify.verify_decision(env, r_deny, snap)[0], "py self-verify DENY failed"
    assert verify.verify_settlement(env, r_allow, settlement, snap)[0], "py self-verify settlement failed"

    bundle = {
        "human_priv": PRIV, "human_pub": pub, "kid": keys.kid_for(pub),
        "now": iso(NOW), "expires_at": EXPIRES, "agent_ref": agent_ref,
        "policy_ref": policy_ref, "allow_ref": allow_ref,
        "envelope": env, "intent_allow": i1, "approval_allow": a1,
        "receipt_allow": r_allow, "ledger_snapshot": snap,
        "intent_deny": i2, "approval_deny": a2, "receipt_deny": r_deny,
        "settlement": settlement, "revoked_envelope": revoked,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False)
    print("wrote", out)
    print("mandate_ref:", env["mandate_ref"])
    print("allow_ref:", allow_ref)
    print("receipt_allow verdict:", r_allow["verdict"], "receipt_deny verdict:", r_deny["verdict"])


if __name__ == "__main__":
    main(sys.argv[1])
