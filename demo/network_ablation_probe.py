"""Compare an open container network with the BCP-1 default-deny boundary."""

from __future__ import annotations

import json
import os
import socket
import urllib.request

from app.action import Action
from app.factory import demo_spki_pin
from app.models import HttpMethod, canonical_json_bytes


def main() -> int:
    expected_blocked = os.environ["EXPECT_PUBLIC_BLOCKED"].lower() == "true"
    try:
        connection = socket.create_connection(("1.1.1.1", 443), timeout=2)
    except OSError:
        public_socket_succeeded = False
    else:
        public_socket_succeeded = True
        connection.close()

    action = Action.build(
        request_id=(
            "request:network-ablation:closed"
            if expected_blocked
            else "request:network-ablation:open"
        ),
        method=HttpMethod.POST,
        host="packages.example.test",
        port=443,
        path="/v1/packages/resolve",
        resolved_ip="203.0.113.17",
        tls_spki_sha256=demo_spki_pin(),
        body={"name": "numpy", "version": "2.0.0"},
        credential_id="credential:package-read",
    )
    request = urllib.request.Request(
        "http://gateway:8000/v1/dispatch",
        data=canonical_json_bytes(action),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        gateway_dispatch_succeeded = response.status == 200

    observed_blocked = not public_socket_succeeded
    result = {
        "boundary": "internal_default_deny" if expected_blocked else "open_bridge",
        "expected_public_socket_blocked": expected_blocked,
        "gateway_dispatch_succeeded": gateway_dispatch_succeeded,
        "public_socket_succeeded": public_socket_succeeded,
        "result_matches_expectation": (
            observed_blocked == expected_blocked and gateway_dispatch_succeeded
        ),
        "scope": "container-network-ablation-only",
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result_matches_expectation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

