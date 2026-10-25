import base64
import json
import unittest
from decimal import Decimal

from policy import (
    PREFERENCES_TYPE,
    Denied,
    check_request,
    check_upload_filename,
    json_object,
    positive_money,
)

HEADERS = {"Content-Type": "application/json"}
CONFIRMATION = "78c3e340-3a2f-4c62-8405-55a64cd1ddeb"


def check(asset, path, value, method="POST", headers=None):
    body = value if isinstance(value, bytes) else json.dumps(value).encode()
    return check_request(asset, method, path, headers or HEADERS, body)


class PolicyTests(unittest.TestCase):
    def test_transfer_positive_and_finite(self):
        for amount in ("100.00", 100, Decimal("0.01")):
            self.assertTrue(positive_money(amount))
        for amount in (
            "-100.00",
            "0",
            "-0",
            "NaN",
            "Infinity",
            "-Infinity",
            "1e100",
            "0.001",
            "1e-999999999",
            "1.001",
            "text",
            True,
            None,
            [],
            0,
        ):
            with self.subTest(amount=amount):
                self.assertFalse(positive_money(amount))
        check(
            "vault",
            "/api/transfers/preview",
            {
                "sourceAccountId": 1,
                "recipientAccountNumber": "TEST-2",
                "amount": "100.00",
            },
        )
        with self.assertRaises(Denied):
            check("vault", "/api/transfers/preview", {"amount": "-100.00"})

    def test_confirmation_cannot_override_preview(self):
        check("vault", "/api/transfers", {"confirmationId": CONFIRMATION})
        for key in ("amount", "sourceAccountId", "recipientAccountNumber"):
            with self.subTest(key=key), self.assertRaises(Denied):
                check(
                    "vault",
                    "/api/transfers",
                    {"confirmationId": CONFIRMATION, key: "overridden"},
                )

    def test_password_reset_owner_remains_bound_to_token(self):
        check(
            "vault",
            "/api/recovery/complete",
            {"token": "opaque", "newPassword": "NewPassword123"},
        )
        for field in ("targetUsername", "targetUserId"):
            with self.assertRaises(Denied):
                check(
                    "vault",
                    "/api/recovery/complete",
                    {
                        "token": "opaque",
                        "newPassword": "NewPassword123",
                        field: "other",
                    },
                )

    def test_preferences_only_known_dto(self):
        check(
            "vault",
            "/api/profile/preferences",
            {
                "@class": PREFERENCES_TYPE,
                "displayName": "Mia",
                "notificationsEnabled": True,
            },
        )
        with self.assertRaises(Denied):
            check(
                "vault",
                "/api/profile/preferences",
                {
                    "@class": "com.bobabank.profile.LabCommandGadget",
                    "command": "benign-fixture",
                },
            )

    def test_statement_plain_text_and_columns(self):
        check(
            "vault",
            "/api/accounts/1/statement/export",
            {"title": "Monthly statement", "columns": ["amount", "createdAt"]},
        )
        for title in ("#{7*7}", "${7*7}", "{{7*7}}", "<#assign x=7>"):
            with self.assertRaises(Denied):
                check("vault", "/api/accounts/1/statement/export", {"title": title})
        with self.assertRaises(Denied):
            check("vault", "/api/accounts/1/statement/export", {"columns": ["#{7*7}"]})

    def test_ldap_filter_is_not_supplied_by_user(self):
        check("vault", "/api/internal/directory?q=jdoe", {}, method="GET")
        with self.assertRaises(Denied):
            check(
                "vault",
                "/api/internal/directory?q=%2A%29%28uid%3D%2A",
                {},
                method="GET",
            )

    def test_registration_cannot_set_privilege(self):
        for value in (
            {"username": "test", "password": "secret"},
            {
                "username": "seller",
                "password": "secret",
                "role": "seller",
                "is_admin": False,
            },
        ):
            check("market", "/api/auth/register", value)
        for value in (
            {"is_admin": True},
            {"is_admin": 1},
            {"role": "admin"},
            {"balance": 100000},
            {"permissions": ["admin"]},
        ):
            with self.assertRaises(Denied):
                check("market", "/api/auth/register", value)

    def test_receipt_header_injection(self):
        check(
            "market",
            "/api/orders/1001/receipt",
            {"email": "user@example.com", "subject": "Receipt"},
        )
        with self.assertRaises(Denied):
            check(
                "market",
                "/api/orders/1001/receipt",
                {
                    "email": "user@example.com\r\nBcc: other@example.com",
                    "subject": "Receipt",
                },
            )

    def test_unsigned_jwt_rejected(self):
        for alg, signature, allowed in (
            ("none", "", False),
            ("none", "fake", False),
            ("RS256", "fake", False),
            ("HS256", "opaque-signature", True),
        ):
            header = (
                base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode())
                .rstrip(b"=")
                .decode()
            )
            headers = {"Authorization": "Bearer " + header + ".e30." + signature}
            if allowed:
                check("market", "/api/admin/panel", {}, method="GET", headers=headers)
            else:
                with self.assertRaises(Denied):
                    check(
                        "market", "/api/admin/panel", {}, method="GET", headers=headers
                    )

    def test_duplicate_and_nonfinite_json(self):
        for body in (
            b'{"amount":"1","amount":"-100"}',
            b'{"amount":NaN}',
            b'{"amount":Infinity}',
            b"[]",
        ):
            with self.assertRaises(Denied):
                json_object(body)
        with self.assertRaises(Denied):
            check(
                "vault",
                "/api/transfers/preview",
                b"amount=100",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        with self.assertRaises(Denied):
            check(
                "vault",
                "/api/transfers/preview",
                {"amount": 100},
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                },
            )

    def test_encoded_paths_do_not_bypass_rules(self):
        for path in (
            "/api/%74ransfers/preview",
            "/api/%2574ransfers/preview",
            "//api//transfers/preview/",
            "/api/./transfers/preview",
        ):
            with self.assertRaises(Denied):
                check("vault", path, {"amount": "-1"})

    def test_vault_internal_endpoints_but_health_stays_open(self):
        for path in ("/actuator/health", "/api/health", "/api/accounts/3"):
            check("vault", path, b"", method="GET")
        for path in (
            "/v3/api-docs",
            "/v3/api-docs.yaml",
            "/v3/api-docs/swagger-config",
            "/swagger-ui/index.html",
            "/swagger-resources/configuration/ui",
            "/actuator",
            "/actuator/env",
            "/Actuator/heapdump",
            "/actuator/health/../env",
        ):
            with self.subTest(path=path), self.assertRaises(Denied):
                check("vault", path, b"", method="GET")

    def test_nether_static_and_uploads(self):
        for path in ("/", "/assets/style.css", "/api/health", "/uploads/photo.jpg"):
            check("nether", path, {}, method="GET")
        for path in (
            "/config.backup",
            "/%63onfig.backup",
            "/.git/config",
            "/uploads/shell.phtml",
            "/uploads/shell.PHP/extra",
        ):
            with self.assertRaises(Denied):
                check("nether", path, {}, method="GET")
        for filename in ("photo.jpg", "document.pdf", "notes.txt"):
            check_upload_filename(filename)
        for filename in (
            "shell.phtml",
            "image.php.jpg",
            ".htaccess",
            "../image.jpg",
            "image.jpg%00.php",
            "script.svg",
        ):
            with self.assertRaises(Denied):
                check_upload_filename(filename)


if __name__ == "__main__":
    unittest.main(verbosity=2)
