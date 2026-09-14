"""Export deterministic JSON Schemas for BCP-1 signed structures."""

from __future__ import annotations

import json
from pathlib import Path

from app.action import Action
from app.models import (
    CancellationEventPayload,
    Decision,
    DispatchEventPayload,
    Event,
    KillAcknowledgement,
    Manifest,
    OverloadSummaryPayload,
    Receipt,
    RequestEventPayload,
    ResultEventPayload,
    SecondHopAttestation,
    ViolationEventPayload,
    WitnessCheckpoint,
)


def main() -> int:
    output = Path("schemas")
    output.mkdir(exist_ok=True)
    models = {
        "action": Action,
        "decision": Decision,
        "event": Event,
        "kill-acknowledgement": KillAcknowledgement,
        "manifest": Manifest,
        "payload-cancellation": CancellationEventPayload,
        "payload-dispatch": DispatchEventPayload,
        "payload-overload-summary": OverloadSummaryPayload,
        "payload-request": RequestEventPayload,
        "payload-result": ResultEventPayload,
        "payload-violation": ViolationEventPayload,
        "receipt": Receipt,
        "second-hop-attestation": SecondHopAttestation,
        "witness-checkpoint": WitnessCheckpoint,
    }
    for name, model in models.items():
        schema = model.model_json_schema()
        encoded = json.dumps(
            schema,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        (output / f"{name}.schema.json").write_text(
            encoded + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
