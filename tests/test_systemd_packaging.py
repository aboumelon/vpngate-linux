from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UNIT_PATH = (
    PROJECT_ROOT / "packaging" / "systemd" / "vpngate-vpnclient.service"
)
INSTALLER_PATH = PROJECT_ROOT / "scripts" / "install-systemd-service.sh"
REMOVER_PATH = PROJECT_ROOT / "scripts" / "remove-systemd-service.sh"


class SystemdPackagingTests(unittest.TestCase):
    def test_unit_uses_foreground_service_mode(self) -> None:
        unit = UNIT_PATH.read_text(encoding="utf-8")

        self.assertIn("Type=exec", unit)
        self.assertIn("vpnclient execsvc", unit)
        self.assertNotIn("vpnclient start", unit)
        self.assertNotIn("vpnclient stop", unit)

    def test_unit_can_write_only_to_its_install_directory(self) -> None:
        unit = UNIT_PATH.read_text(encoding="utf-8")

        self.assertIn("ProtectSystem=full", unit)
        self.assertIn("ProtectHome=yes", unit)
        self.assertIn("ReadWritePaths=/usr/local/vpnclient", unit)

    def test_installer_does_not_copy_existing_runtime_configuration(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        self.assertNotIn("vpn_client.config", installer)
        self.assertNotIn("AccountConnect", installer)
        self.assertNotIn("dhclient", installer)
        self.assertNotIn("resolvectl", installer)

    def test_management_tool_is_available_without_exposing_the_daemon_binary(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        self.assertIn('-m 0755 "${INSTALL_DIR}"', installer)
        self.assertIn('-m 0700 "${SOURCE_DIR}/vpnclient"', installer)
        self.assertIn('-m 0755 "${SOURCE_DIR}/vpncmd"', installer)
        self.assertIn('-m 0644 "${SOURCE_DIR}/hamcore.se2"', installer)

    def test_remover_preserves_runtime_configuration(self) -> None:
        remover = REMOVER_PATH.read_text(encoding="utf-8")

        self.assertNotIn("rm -rf", remover)
        self.assertNotIn('rm -- "${INSTALL_DIR}"', remover)
        self.assertIn("SoftEther files and runtime configuration were preserved", remover)


if __name__ == "__main__":
    unittest.main()
