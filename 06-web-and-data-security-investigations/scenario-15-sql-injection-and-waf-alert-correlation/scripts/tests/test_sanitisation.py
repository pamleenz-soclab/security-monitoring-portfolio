#!/usr/bin/env python3
import re, unittest

def clean(value: str) -> str:
    return re.sub(r'(?i)(cookie|authorization|token|session)[^\s,;]*', '[REDACTED]', value)

class SanitisationTests(unittest.TestCase):
    def test_cookie_token_is_removed(self):
        self.assertNotIn('abcdef', clean('CookieToken=abcdef'))
    def test_sql_fragment_is_retained(self):
        self.assertIn('sleep(15)', clean('sleep(15)'))

if __name__ == '__main__': unittest.main()
