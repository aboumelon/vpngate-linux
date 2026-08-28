from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class AppArmorPackagingTests(unittest.TestCase):
    def test_policy_is_limited_to_project_runtime_files(self) -> None:
        policy = (
            PROJECT_ROOT / "packaging" / "apparmor" / "vpngate-linux-dhclient"
        ).read_text(encoding="utf-8")

        self.assertNotIn("/**", policy)
        self.assertIn("/run/vpngate-linux/dhclient-address-only.conf r,", policy)
        self.assertIn("/run/vpngate-linux/dhclient-address-only Uxr,", policy)
        self.assertIn("/run/vpngate-linux/dhclient.leases lrw,", policy)
        self.assertIn("/run/vpngate-linux/dhclient.pid lrw,", policy)

    def test_installer_uses_a_separate_included_policy(self) -> None:
        installer = (
            PROJECT_ROOT / "scripts" / "install-dhclient-apparmor-policy.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("#include <vpngate-linux-dhclient>", installer)
        self.assertNotIn("setenforce", installer)
        self.assertNotIn("aa-disable", installer)


if __name__ == "__main__":
    unittest.main()
