import unittest

from rewrite_test_framework import ROOT, load_cases, run_matrix


class RewriteFrameworkTests(unittest.TestCase):
    def test_instruction_policy_matrix(self):
        path = ROOT / "tests/rewrite_cases.json"
        cases = load_cases(path)
        results = run_matrix(path)
        self.assertEqual(len(results), len(cases))
        self.assertGreaterEqual(len(results), 15)
        self.assertTrue(any(item["status"] == "rejected" for item in results))
        self.assertTrue(any(item["status"] == "accepted" for item in results))


if __name__ == "__main__":
    unittest.main()
