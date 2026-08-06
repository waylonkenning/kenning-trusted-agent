import unittest

from scripts.release_identity import load_name_catalog, release_identity, validate_release_identity


class ReleaseIdentityTests(unittest.TestCase):
    def test_catalog_is_ordered_unique_and_sourced_from_linz(self):
        catalog = load_name_catalog()
        names = catalog["names"]
        self.assertGreaterEqual(len(names), 100)
        self.assertEqual(len({name.casefold() for name in names}), len(names))
        self.assertIn("linz.govt.nz", catalog["source"])

    def test_sequence_resolves_name_and_semantic_version(self):
        first = release_identity(release_id="development-aws-1", sequence=1)
        later = release_identity(release_id="development-aws-92", sequence=92)
        self.assertEqual(first["release_version"], "0.1.1")
        self.assertEqual(first["release_name_position"], 1)
        self.assertEqual(later["release_version"], "0.1.92")
        self.assertEqual(later["release_name"], "Waitomo")
        self.assertEqual(later["release_name_position"], 92)

    def test_catalog_cycles_without_changing_the_sequence(self):
        catalog = load_name_catalog()
        repeated = release_identity(release_id="release-101", sequence=len(catalog["names"]) + 1)
        self.assertEqual(repeated["release_name"], catalog["names"][0])
        self.assertEqual(repeated["release_name_cycle"], 2)
        self.assertEqual(repeated["release_sequence"], len(catalog["names"]) + 1)

    def test_identity_validation_binds_release_id(self):
        identity = release_identity(release_id="release-7", sequence=7)
        validate_release_identity(identity, expected_release_id="release-7")
        identity["release_id"] = "release-8"
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_release_identity(identity, expected_release_id="release-7")

    def test_invalid_sequence_and_version_are_rejected(self):
        with self.assertRaises(ValueError):
            release_identity(release_id="release-0", sequence=0)
        with self.assertRaises(ValueError):
            release_identity(release_id="release-invalid", sequence=1, release_version="not-a-version")


if __name__ == "__main__":
    unittest.main()
