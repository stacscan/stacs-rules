"""Tests all STACS rules."""

import os
import unittest
import glob
import yara


class STACSRules(unittest.TestCase):
    """Tests all STACS rules."""

    def setUp(self):
        """Ensure the application is setup for testing."""
        self.test_path = os.path.dirname(os.path.abspath(__file__))
        self.rules_path = os.path.abspath(os.path.join(self.test_path, "../rules"))
        self.fixtures_path = os.path.join(self.test_path, "fixtures/")

    def tearDown(self):
        """Ensure everything is torn down between tests."""
        pass

    def test_all_rules(self):
        """Run all rules independently and check for false positives and negatives."""
        rules = glob.glob(f"{self.rules_path}/**/*.yar", recursive=True)

        for rule in rules:
            # Load the rule.
            matcher = yara.compile(filepath=rule)
            parent_path = os.path.join(
                self.fixtures_path,
                rule.replace(os.path.dirname(self.rules_path), "").lstrip("/rules/"),
            )

            # Ensure that there's at least one 'negative' fixture.
            candidates = glob.glob(f"{parent_path}/negative/**/*", recursive=True)
            with self.subTest(f"Missing negative fixtures {rule}"):
                self.assertGreater(len(candidates), 0)

            # Run through all 'negative' fixtures and ensure they don't match.
            for candidate in candidates:
                with self.subTest(f"Negative test of {rule} against {candidate}"):
                    if os.path.isfile(candidate):
                        self.assertEqual(len(matcher.match(candidate)), 0)

            # Ensure that there's at least one 'positive' fixture.
            candidates = glob.glob(f"{parent_path}/positive/**/*", recursive=True)
            with self.subTest(f"Missing positive fixtures {rule}"):
                self.assertGreater(len(candidates), 0)

            # Run through all 'positive' fixtures and ensure they have matches.
            for candidate in candidates:
                with self.subTest(f"Positive test of {rule} against {candidate}"):
                    if os.path.isfile(candidate):
                        self.assertGreaterEqual(len(matcher.match(candidate)), 1)
