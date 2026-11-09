import re
import unittest

import minecraft


# distutils.version was removed in Python 3.12; the check it performed —
# that __version__ is a strict N.N[.N] version — is a one-line regex.
STRICT_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


class VersionTest(unittest.TestCase):
    def test_module_version_is_a_valid_pep_386_strict_version(self):
        self.assertRegex(minecraft.__version__, STRICT_VERSION_RE)

    def test_protocol_version_is_an_int(self):
        for version in minecraft.SUPPORTED_PROTOCOL_VERSIONS:
            self.assertTrue(type(version) is int)
