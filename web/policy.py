import base64
import json
import posixpath
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID

MAX_BODY = 1_048_576
PREFERENCES_TYPE = "com.bobabank.profile.dto.PreferencesDto"
SCRIPT_EXTENSION = re.compile(
    r"\.(?:php\d*|phtml|phar|cgi|pl|py|sh|jsp|jspx|asp|aspx)(?:[./;]|$)", re.IGNORECASE
)
UPLOAD_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt"}


class Denied(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate_json_key")
        result[key] = value
    return result


def invalid_constant(value):
    raise Denied("nonfinite_json_number")


def json_object(body):
    if len(body) > MAX_BODY:
        raise Denied("body_size")
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_float=Decimal,
            parse_constant=invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied("json") from exc
    if not isinstance(value, dict):
        raise Denied("json_object")
    return value


def canonical_path(target):
    try:
        split = urlsplit(target)
        if split.scheme or split.netloc or not target.startswith("/"):
            raise Denied("path_authority")
        path = split.path
        for _ in range(3):
            decoded = unquote(path, errors="strict")
            if decoded == path:
                break
            path = decoded
    except (ValueError, UnicodeError) as exc:
        raise Denied("path_encoding") from exc
    if any(ord(c) < 32 for c in path) or "\\" in path or ";" in path or "%" in path:
        raise Denied("ambiguous_path")
    return posixpath.normpath("/" + path.lstrip("/")).lower()


def ordinary_text(value, maximum=200):
    return (
        isinstance(value, str)
        and len(value) <= maximum
        and all(
            unicodedata.category(c)[0] in "LMN"
            or c in " .,:;!?()-_/\u2019\u02bb\u02bc#\u2116&\"'\u00ab\u00bb\u2014\u2013+"
            for c in value
        )
    )


def positive_money(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        return False
    if len(str(value)) > 24:
        return False
    try:
        amount = Decimal(value)
    except (InvalidOperation, ValueError):
        return False
    return (
        amount.is_finite()
        and Decimal("0.01") <= amount <= Decimal("92233720368547758.07")
        and amount * 100 == (amount * 100).to_integral_value()
    )


def safe_ldap_text(value):
    return (
        isinstance(value, str)
        and not any(c in value for c in "*()\\\x00")
        and all(ord(c) >= 32 for c in value)
    )


def check_jwt(authorization):
    if not authorization:
        return
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return
    parts = token.split(".")
    if len(parts) != 3 or not parts[2] or len(token) > 16384:
        raise Denied("jwt_structure")
    try:
        raw = base64.b64decode(
            parts[0] + "=" * (-len(parts[0]) % 4), altchars=b"-_", validate=True
        )
        header = json_object(raw)
    except (ValueError, UnicodeError) as exc:
        raise Denied("jwt_header") from exc
    if header.get("alg") != "HS256":
        raise Denied("jwt_algorithm")


def check_upload_filename(filename):
    if not isinstance(filename, str) or not filename or len(filename) > 200:
        raise Denied("upload_filename")
    if filename.startswith(".") or any(c in filename for c in "/\\%;\x00\r\n"):
        raise Denied("upload_filename")
    extension = posixpath.splitext(filename.lower())[1]
    if extension not in UPLOAD_EXTENSIONS or SCRIPT_EXTENSION.search(filename):
        raise Denied("upload_type")


def check_request(asset, method, target, headers, body):
    path = canonical_path(target)
    headers = {key.lower(): value for key, value in headers.items()}
    if asset == "nether":
        if path in ("/config.backup", "/.env") or path.startswith("/.git/"):
            raise Denied("configuration_disclosure")
        if path.startswith("/uploads/") and SCRIPT_EXTENSION.search(path):
            raise Denied("uploaded_script")
        return
    if asset == "vault" and (
        path.startswith(("/v3/api-docs", "/swagger-ui", "/swagger-resources"))
        or (path.startswith("/actuator") and path != "/actuator/health")
    ):
        raise Denied("internal_endpoint")
    if asset == "market":
        check_jwt(headers.get("authorization", ""))
    if asset == "vault" and path == "/api/internal/directory":
        try:
            queries = parse_qs(
                urlsplit(target).query, keep_blank_values=True, max_num_fields=50
            )
        except ValueError as exc:
            raise Denied("query_fields") from exc
        for values in queries.values():
            if any(not safe_ldap_text(value) for value in values):
                raise Denied("ldap_query")
    guarded = (
        asset == "vault"
        and (
            path
            in (
                "/api/transfers/preview",
                "/api/transfers",
                "/api/recovery/complete",
                "/api/profile/preferences",
                "/api/auth/internal-login",
            )
            or re.fullmatch(r"/api/accounts/[^/]+/statement/export", path)
        )
        or asset == "market"
        and (
            path == "/api/auth/register"
            or re.fullmatch(r"/api/orders/[^/]+/receipt", path)
        )
    )
    if not guarded or method.upper() in ("GET", "HEAD", "OPTIONS"):
        return
    media = headers.get("content-type", "").partition(";")[0].strip().lower()
    if (
        media != "application/json"
        or headers.get("content-encoding", "identity").lower() != "identity"
    ):
        raise Denied("json_content_type")
    value = json_object(body)
    if asset == "vault":
        if path == "/api/transfers/preview" and not positive_money(value.get("amount")):
            raise Denied("transfer_amount")
        if path == "/api/transfers":
            if set(value) != {"confirmationId"} or not isinstance(
                value["confirmationId"], str
            ):
                raise Denied("confirmation_override")
            try:
                UUID(value["confirmationId"])
            except ValueError as exc:
                raise Denied("confirmation_id") from exc
        if path == "/api/recovery/complete" and any(
            k in value for k in ("targetUsername", "targetUserId")
        ):
            raise Denied("reset_target_override")
        if path == "/api/profile/preferences":
            if set(value) - {"@class", "displayName", "notificationsEnabled"}:
                raise Denied("preferences_fields")
            if "@class" in value and value["@class"] != PREFERENCES_TYPE:
                raise Denied("preferences_type")
        if path == "/api/auth/internal-login" and not safe_ldap_text(
            value.get("username", "")
        ):
            raise Denied("ldap_username")
        if path.endswith("/statement/export"):
            if not ordinary_text(value.get("title", "")):
                raise Denied("statement_title")
            columns = value.get("columns", [])
            if (
                not isinstance(columns, list)
                or len(columns) > 30
                or any(not ordinary_text(c, 80) for c in columns)
            ):
                raise Denied("statement_columns")
    if asset == "market" and path.endswith("/receipt"):
        for key in ("email", "subject"):
            if key in value and (
                not isinstance(value[key], str)
                or any(c in value[key] for c in "\r\n\x00")
            ):
                raise Denied("receipt_header_injection")
    if asset == "market" and path == "/api/auth/register":
        if set(value) - {"username", "password", "email", "role", "is_admin"}:
            raise Denied("registration_fields")
        if value.get("is_admin", False) is not False or value.get(
            "role", "buyer"
        ) not in ("buyer", "seller"):
            raise Denied("registration_privilege")
