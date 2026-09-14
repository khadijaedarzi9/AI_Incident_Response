"""Container-network smoke test; not a substitute for microVM conformance."""

from __future__ import annotations

import json
import socket
import urllib.request

from app.action import Action
from app.factory import demo_spki_pin
from app.models import HttpMethod, canonical_json_bytes


def main() -> int:
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=1)
    except OSError:
        raw_socket_blocked = True
    else:
        raw_socket_blocked = False

    action = Action.build(
        request_id="request:boundary-probe",
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
        gateway_status = response.status
    result = {
        "gateway_dispatch_succeeded": gateway_status == 200,
        "raw_public_socket_blocked": raw_socket_blocked,
        "scope": "container-network-smoke-test-only",
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if all((result["gateway_dispatch_succeeded"], raw_socket_blocked)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
