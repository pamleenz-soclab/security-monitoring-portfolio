#!/usr/bin/env python3
import unittest

from scripts.build_reproduction_sample import clean


class SanitisationTests(unittest.TestCase):
    def test_cookie_token_is_removed(self):
        self.assertNotIn("abcdef", clean("CookieToken=abcdef"))

    def test_authorization_value_is_removed(self):
        self.assertNotIn("secretvalue", clean("Authorization=secretvalue"))

    def test_sql_fragment_is_retained(self):
        self.assertIn("sleep(15)", clean("sleep(15)"))


if __name__ == "__main__":
    unittest.main()
