import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cveRisk


class CveRiskPressureCallTests(unittest.TestCase):
    @patch("cveRisk.requests.get")
    def test_fetch_uses_profile_cve_and_readonly_viewer(self, get):
        get.return_value.json.return_value = {"cve_id": "CVE-2026-83548"}

        pressure = cveRisk.fetch_attack_pressure("CVE-2026-83548")

        self.assertEqual("CVE-2026-83548", pressure["cve_id"])
        get.assert_called_once_with(
            "http://127.0.0.1:5001/api/v1/long-term/attack-pressure",
            params={"profile": "healthcare_europe", "cve": "CVE-2026-83548"},
            timeout=10,
        )
        get.return_value.raise_for_status.assert_called_once_with()

    @patch("cveRisk.fetch_attack_pressure")
    @patch("cveRisk.TEFCalculator")
    def test_main_passes_each_pressure_to_calculate_tef(self, calculator_type, fetch):
        fetch.side_effect = lambda cve: {"cve_id": cve, "tef_adjustment": {"factor": 1.2}}
        calculator = calculator_type.return_value
        calculator.calculate_tef.side_effect = lambda cve, pressure=None: {
            "epss": 0.5, "epss_annual": 0.99978,
            "percentile": 0.8, "in_cisa_kev": False,
            "min": 0.1, "mode": 0.2, "max": 0.3,
            "pressure_factor": pressure["tef_adjustment"]["factor"],
        }

        with redirect_stdout(io.StringIO()):
            cveRisk.main()

        self.assertEqual(3, fetch.call_count)
        self.assertEqual(3, calculator.calculate_tef.call_count)
        for arguments in calculator.calculate_tef.call_args_list:
            cve = arguments.args[0]
            self.assertEqual(cve, arguments.kwargs["pressure"]["cve_id"])

    @patch("cveRisk.fetch_attack_pressure", side_effect=requests.ConnectionError("offline"))
    @patch("cveRisk.TEFCalculator")
    def test_unavailable_viewer_keeps_baseline_tef(self, calculator_type, fetch):
        calculator = calculator_type.return_value
        calculator.calculate_tef.return_value = {
            "epss": 0.5, "epss_annual": 0.99978,
            "percentile": 0.8, "in_cisa_kev": False,
            "min": 0.1, "mode": 0.2, "max": 0.3,
        }

        output = io.StringIO()
        with redirect_stdout(output):
            cveRisk.main()

        self.assertEqual(3, calculator.calculate_tef.call_count)
        self.assertTrue(all(
            arguments.kwargs["pressure"] is None
            for arguments in calculator.calculate_tef.call_args_list
        ))
        self.assertIn("Attack pressure unavailable", output.getvalue())


if __name__ == "__main__":
    unittest.main()
