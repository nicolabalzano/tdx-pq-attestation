#!/usr/bin/env python3
"""Small local PCS-compatible proxy for private TD_QE identity testing.

The server forwards Intel PCS-compatible collateral requests upstream, except
for TDX QE identity. That endpoint is served from a local JSON file generated
from the quote's embedded QE report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


FORWARDED_HEADERS = {
    "cache-control",
    "content-type",
    "request-id",
    "sgx-enclave-identity-issuer-chain",
    "sgx-pck-certificate-issuer-chain",
    "sgx-pck-crl-issuer-chain",
    "sgx-tcb-info-issuer-chain",
    "tcb-info-issuer-chain",
}


def build_upstream_url(origin: str, path: str, query: str) -> str:
    parsed = urllib.parse.urlsplit(origin)
    if not parsed.netloc:
        parsed = urllib.parse.urlsplit("https://" + origin)
    scheme = parsed.scheme or "https"
    return urllib.parse.urlunsplit((scheme, parsed.netloc, path, query, ""))


class LocalPcsHandler(BaseHTTPRequestHandler):
    server_version = "LocalTdxPcsProxy/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[local-pcs] " + fmt % args + "\n")
        sys.stderr.flush()

    @property
    def identity_file(self) -> Path:
        return self.server.identity_file  # type: ignore[attr-defined]

    @property
    def upstream_origin(self) -> str:
        return self.server.upstream_origin  # type: ignore[attr-defined]

    def send_bytes(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, body, {"Content-Type": "application/json"})

    def fetch(self, url: str) -> tuple[int, bytes, dict[str, str]]:
        headers = {
            "Accept": "*/*",
            "User-Agent": "local-tdx-pcs-proxy/1.0",
        }
        subscription_key = os.environ.get(self.server.subscription_key_env)  # type: ignore[attr-defined]
        if subscription_key:
            headers["Ocp-Apim-Subscription-Key"] = subscription_key

        req = urllib.request.Request(
            url,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read(), self.filtered_headers(resp.headers.items())
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), self.filtered_headers(exc.headers.items())

    @staticmethod
    def filtered_headers(items: object) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in items:
            key_lc = key.lower()
            if key_lc in FORWARDED_HEADERS:
                headers[key] = value
        return headers

    def read_local_identity(self) -> bytes:
        if not self.identity_file.exists():
            raise FileNotFoundError(str(self.identity_file))
        return self.identity_file.read_bytes()

    def handle_identity(self, path: str, query: str) -> None:
        upstream_url = build_upstream_url(self.upstream_origin, path, query)
        status, _, headers = self.fetch(upstream_url)
        if status != 200:
            self.send_json(
                502,
                {
                    "error": "upstream_tdqe_identity_unavailable",
                    "upstream_status": status,
                    "upstream": upstream_url,
                },
            )
            return

        issuer_chain = None
        for key, value in headers.items():
            if key.lower() == "sgx-enclave-identity-issuer-chain":
                issuer_chain = value
                break
        if not issuer_chain:
            self.send_json(502, {"error": "upstream_tdqe_identity_missing_issuer_chain"})
            return

        try:
            body = self.read_local_identity()
        except FileNotFoundError:
            self.send_json(
                503,
                {
                    "error": "local_tdqe_identity_not_ready",
                    "identity_file": str(self.identity_file),
                },
            )
            return

        self.send_bytes(
            200,
            body,
            {
                "Content-Type": "application/json",
                "sgx-enclave-identity-issuer-chain": issuer_chain,
                "Cache-Control": "no-store",
            },
        )

    def handle_crl_uri(self, query: str) -> bool:
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        uri_values = params.get("uri")
        if not uri_values:
            return False
        status, body, headers = self.fetch(uri_values[0])
        self.send_bytes(status, body, headers)
        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = parsed.query

        if path == "/healthz":
            self.send_json(200, {"ok": True})
            return

        if path == "/tdx/certification/v4/qe/identity":
            self.handle_identity(path, query)
            return

        if path.endswith("/crl") and self.handle_crl_uri(query):
            return

        upstream_url = build_upstream_url(self.upstream_origin, path, query)
        status, body, headers = self.fetch(upstream_url)
        self.send_bytes(status, body, headers)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--identity-file", required=True)
    parser.add_argument(
        "--upstream-origin",
        default="https://api.trustedservices.intel.com",
        help="Intel PCS origin used for pass-through collateral",
    )
    parser.add_argument(
        "--subscription-key-env",
        default="INTEL_PCS_API_KEY",
        help="optional environment variable containing an Intel PCS subscription key for upstream requests",
    )
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), LocalPcsHandler)
    server.identity_file = Path(args.identity_file)  # type: ignore[attr-defined]
    server.upstream_origin = args.upstream_origin.rstrip("/")  # type: ignore[attr-defined]
    server.subscription_key_env = args.subscription_key_env  # type: ignore[attr-defined]
    print(
        f"[local-pcs] serving on http://{args.host}:{args.port}, "
        f"identity_file={server.identity_file}, upstream={server.upstream_origin}",
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
