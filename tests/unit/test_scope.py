import unittest

from enigma.authorization.scope import ScopeGuard
from enigma.core.assessment import Scope


class ScopeGuardTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(
            allowed_hosts=["authorized-target.example"],
            excluded_paths=["/logout", "/account/delete"],
        )
        self.guard = ScopeGuard(self.scope)

    def test_allows_in_scope_host(self):
        decision = self.guard.check_url("https://authorized-target.example/search")
        self.assertTrue(decision.allowed, decision.reason)

    def test_blocks_out_of_scope_host(self):
        decision = self.guard.check_url("https://not-authorized.example/")
        self.assertFalse(decision.allowed)
        self.assertIn("allowed_hosts", decision.reason)

    def test_blocks_excluded_path(self):
        decision = self.guard.check_url("https://authorized-target.example/logout")
        self.assertFalse(decision.allowed)
        self.assertIn("excluded", decision.reason)

    def test_excluded_path_prefix(self):
        decision = self.guard.check_url("https://authorized-target.example/account/delete/confirm")
        self.assertFalse(decision.allowed)

    def test_similar_path_not_excluded(self):
        decision = self.guard.check_url("https://authorized-target.example/logout-help")
        self.assertTrue(decision.allowed, decision.reason)

    def test_port_restriction(self):
        scope = Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000])
        guard = ScopeGuard(scope)
        self.assertTrue(guard.check_url("http://127.0.0.1:8000/").allowed)
        self.assertFalse(guard.check_url("http://127.0.0.1:9000/").allowed)


if __name__ == "__main__":
    unittest.main()
