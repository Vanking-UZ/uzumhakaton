import json
import logging
import os
import sys
from email import policy as mail_policy
from email.parser import BytesParser
from pathlib import Path

from mitmproxy import http

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import (
    MAX_BODY,
    Denied,
    canonical_path,
    check_request,
    check_upload_filename,
)


class Guard:
    def __init__(self):
        self.asset = os.environ.get("GUARD_ASSET", "")
        self.public_host = os.environ.get("GUARD_PUBLIC_HOST", "")
        self.allowed_origins = set(
            filter(None, os.environ.get("GUARD_ALLOWED_ORIGINS", "").split(","))
        )
        if self.asset not in ("vault", "market", "nether"):
            raise ValueError("GUARD_ASSET must be vault, market, or nether")
        if self.asset == "market" and not self.public_host:
            raise ValueError("GUARD_PUBLIC_HOST is required for Market")
        if any(c in self.public_host for c in "\r\n/\\"):
            raise ValueError("GUARD_PUBLIC_HOST must be a host[:port]")

    def deny(self, flow, reason):
        flow.response = http.Response.make(
            403,
            b'{"error":"Forbidden"}\n',
            {"Content-Type": "application/json", "Cache-Control": "no-store"},
        )
        logging.info("GUARD DROP asset=%s reason=%s", self.asset, reason)

    def request(self, flow: http.HTTPFlow):
        try:
            check_request(
                self.asset,
                flow.request.method,
                flow.request.path,
                dict(flow.request.headers),
                flow.request.raw_content or b"",
            )
            path = canonical_path(flow.request.path)
            flow.metadata["guard_path"] = path
            if self.asset == "market":
                for name in list(flow.request.headers):
                    if name.lower().startswith("x-forwarded-") or name.lower() in (
                        "forwarded",
                        "x-original-host",
                        "x-host",
                        "x-http-host-override",
                    ):
                        del flow.request.headers[name]
                flow.request.headers["Host"] = self.public_host
            if (
                self.asset == "nether"
                and path == "/api/upload"
                and flow.request.method.upper() == "POST"
            ):
                content_type = flow.request.headers.get("content-type", "")
                raw = flow.request.raw_content or b""
                if (
                    len(raw) > MAX_BODY
                    or flow.request.headers.get("content-encoding", "identity").lower()
                    != "identity"
                ):
                    raise Denied("upload_body_size_or_encoding")
                if not content_type.lower().startswith("multipart/form-data;"):
                    raise Denied("upload_content_type")
                envelope = (
                    "Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n"
                ).encode("latin1") + raw
                message = BytesParser(policy=mail_policy.default).parsebytes(envelope)
                if not message.is_multipart() or message.defects:
                    raise Denied("upload_multipart")
                found = False
                for part in message.walk():
                    if part.defects or any(
                        getattr(header, "defects", ()) for _, header in part.items()
                    ):
                        raise Denied("upload_multipart")
                    if any(
                        len(part.get_all(name, [])) > 1
                        for name in ("Content-Type", "Content-Disposition")
                    ):
                        raise Denied("upload_duplicate_header")
                    filename = part.get_filename()
                    if filename is not None:
                        found = True
                        check_upload_filename(filename)
                if not found:
                    raise Denied("upload_file_missing")
            flow.response = None
        except (Denied, ValueError, UnicodeError, RecursionError):
            self.deny(flow, "policy")

    def response(self, flow: http.HTTPFlow):
        if (
            self.asset == "vault"
            and flow.response
            and flow.metadata.get("guard_path") == "/api/recovery/request"
            and flow.response.status_code in (200, 404)
        ):
            flow.response.status_code = 200
            flow.response.content = json.dumps(
                {
                    "status": "SENT",
                    "message": "If the account exists, recovery instructions have been sent.",
                }
            ).encode()
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.headers["Cache-Control"] = "no-store"
        if (
            self.asset == "market"
            and flow.response
            and flow.metadata.get("guard_path") == "/config"
        ):
            try:
                value = json.loads(flow.response.content or b"")
                if not isinstance(value, dict):
                    raise ValueError("configuration_shape")
                private = {
                    "jwt_secret",
                    "api_secret",
                    "db_dsn",
                    "data_dir",
                    "mgmt_addr",
                    "admin_vhost",
                    "metadata_base",
                    "collector_base",
                }
                value = {
                    key: item
                    for key, item in value.items()
                    if key.lower() not in private
                }
                flow.response.content = json.dumps(value).encode()
                flow.response.headers["Content-Type"] = "application/json"
                flow.response.headers["Cache-Control"] = "no-store"
            except (ValueError, UnicodeError):
                self.deny(flow, "configuration_shape")
        if self.asset == "market" and flow.response:
            origin = flow.request.headers.get("origin")
            if origin and origin not in self.allowed_origins:
                for name in (
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                ):
                    if name in flow.response.headers:
                        del flow.response.headers[name]


addons = [Guard()]
