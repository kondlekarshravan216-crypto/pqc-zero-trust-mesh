"""Static regression tests for Docker Compose network boundaries.

Run from the repository root:
    python3 tests/test_compose_network_isolation.py
"""

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"


class ComposeNetworkIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        cls.services = cls.compose["services"]

    def networks(self, service):
        configured = self.services[service].get("networks", [])
        if isinstance(configured, dict):
            return set(configured)
        return set(configured)

    def test_backend_app_is_only_on_private_backend_network(self):
        self.assertEqual(self.networks("backend-app"), {"backend_internal"})

    def test_frontend_envoy_cannot_join_backend_or_opa_networks(self):
        self.assertEqual(self.networks("frontend-envoy"), {"frontend_backend"})

    def test_backend_envoy_bridges_the_three_required_networks(self):
        self.assertEqual(
            self.networks("backend-envoy"),
            {"frontend_backend", "backend_internal", "opa_authz"},
        )

    def test_opa_is_only_on_the_authorization_network(self):
        self.assertEqual(self.networks("opa-service"), {"opa_authz"})

    def test_private_networks_are_internal(self):
        networks = self.compose["networks"]
        self.assertTrue(networks["backend_internal"].get("internal", False))
        self.assertTrue(networks["opa_authz"].get("internal", False))

    def test_published_ports_are_loopback_only(self):
        for service in ("frontend-envoy", "backend-envoy", "opa-service"):
            for mapping in self.services[service].get("ports", []):
                host = str(mapping).split(":", 1)[0]
                self.assertEqual(host, "127.0.0.1", f"{service} exposes {mapping}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
