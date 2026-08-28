from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def test_installer_uses_only_the_supplied_softether_source(self) -> None:
        installer = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertNotIn("wget", installer)
        self.assertNotIn("apt-get", installer)
        self.assertIn("install-systemd-service.sh", installer)
        self.assertIn("install-dhclient-apparmor-policy.sh", installer)

    def test_real_verifier_always_installs_a_cleanup_trap(self) -> None:
        verifier = (
            PROJECT_ROOT / "scripts" / "verify-real-connection.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("trap cleanup EXIT INT TERM", verifier)
        self.assertIn("disconnect --apply", verifier)
        self.assertIn("recover --apply", verifier)
        self.assertIn("verify", verifier)

    def test_namespace_verifier_covers_apply_and_remove(self) -> None:
        verifier = (
            PROJECT_ROOT / "scripts" / "verify-network-namespace.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("route add 0.0.0.0/1", verifier)
        self.assertIn("route del 0.0.0.0/1", verifier)
        self.assertIn("rule add priority", verifier)
        self.assertIn("rule del priority", verifier)


if __name__ == "__main__":
    unittest.main()
