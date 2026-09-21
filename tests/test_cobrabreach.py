import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cobrabreach import (
    BreachLookupError,
    PasswordResult,
    check_password_local,
    check_password_online,
    load_local_db,
    sha1_hex,
)


class Sha1Tests(unittest.TestCase):
    def test_sha1_hex_matches_known_vector(self) -> None:
        # SHA-1("password") is a well-known constant.
        self.assertEqual(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        )


class OnlineLookupTests(unittest.TestCase):
    @staticmethod
    def _fake_response(body: str):
        # urlopen's response.read() yields bytes, so the fake must too.
        class _Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Response(body.encode("utf-8"))

    def test_k_anonymity_sends_only_prefix(self) -> None:
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            digest = sha1_hex("password")
            return self._fake_response(f"{digest[5:]}:3861493\r\nAAAAAAAABBBB:1\r\n")

        with patch("urllib.request.urlopen", fake_urlopen):
            result = check_password_online("password")

        # Only the 5-char prefix may appear in the request URL.
        self.assertTrue(captured["url"].endswith("/range/5BAA6"))
        self.assertNotIn(sha1_hex("password"), captured["url"])
        self.assertEqual(result.count, 3_861_493)
        self.assertTrue(result.breached)
        self.assertEqual(result.source, "hibp-k-anonymity")

    def test_clean_password_returns_zero(self) -> None:
        with patch(
            "urllib.request.urlopen",
            lambda request, timeout=0: self._fake_response("0123456789AB:7\r\n"),
        ):
            result = check_password_online("a-very-unique-passphrase")
        self.assertEqual(result.count, 0)
        self.assertFalse(result.breached)


class LocalDbTests(unittest.TestCase):
    def test_loads_hash_and_count_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "db.txt"
            known = sha1_hex("hunter2")
            db_path.write_text(
                f"# comment line\n{known}:42\n{'A' * 40}\n", encoding="utf-8"
            )
            database = load_local_db(db_path)

        self.assertEqual(database[known], 42)
        self.assertEqual(database["A" * 40], 1)  # plain hash defaults to count 1

    def test_rejects_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "db.txt"
            db_path.write_text("not-a-hash\n", encoding="utf-8")
            with self.assertRaises(BreachLookupError):
                load_local_db(db_path)

    def test_local_lookup(self) -> None:
        database = {sha1_hex("hunter2"): 7}
        hit = check_password_local("hunter2", database)
        miss = check_password_local("correct horse battery staple", database)
        self.assertEqual(hit.count, 7)
        self.assertTrue(hit.breached)
        self.assertFalse(miss.breached)


class ResultTests(unittest.TestCase):
    def test_breached_property(self) -> None:
        self.assertTrue(PasswordResult(digest="x" * 40, count=1, source="local-db").breached)
        self.assertFalse(PasswordResult(digest="x" * 40, count=0, source="local-db").breached)


if __name__ == "__main__":
    unittest.main()
