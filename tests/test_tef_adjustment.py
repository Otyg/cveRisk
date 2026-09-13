import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cveTef import TEFCalculator, annualize_epss, apply_tef_adjustment


class TefAdjustmentTests(unittest.TestCase):
    def test_calculator_applies_matching_bounded_factor_without_network(self):
        calculator = TEFCalculator.__new__(TEFCalculator)
        calculator.get_epss_score = lambda cve: (0.5, 0.9)
        calculator.is_in_cisa_kev = lambda cve: False
        pressure = {
            "cve_id": "CVE-2026-12345",
            "status": "assessed",
            "tef_adjustment": {"method": "multiply", "factor": 1.2},
            "evidence": {"report_id": "report-1"},
        }
        baseline = calculator.calculate_tef("CVE-2026-12345")
        adjusted = calculator.calculate_tef("CVE-2026-12345", pressure)
        self.assertEqual(0.8, baseline["mode"])
        self.assertEqual(0.96, adjusted["mode"])
        self.assertEqual(0.5, baseline["epss"])
        self.assertGreater(baseline["epss_annual"], 0.999)
        self.assertEqual(365, baseline["tef_horizon_days"])
        self.assertEqual("report-1", adjusted["pressure_report_id"])
        self.assertEqual(baseline["epss"], adjusted["epss"])

    def test_annualization_matches_constant_hazard_model(self):
        expected = 1 - (1 - 0.1) ** (365 / 30)
        self.assertAlmostEqual(expected, annualize_epss(0.1))
        self.assertEqual(0.0, annualize_epss(0.0))
        self.assertEqual(1.0, annualize_epss(1.0))
        for invalid in (-0.1, 1.1, float("nan")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                annualize_epss(invalid)

    def test_small_epss_changes_annual_tef_while_preserving_30_day_value(self):
        calculator = TEFCalculator.__new__(TEFCalculator)
        calculator.get_epss_score = lambda cve: (0.01, 0.9)
        calculator.is_in_cisa_kev = lambda cve: False
        result = calculator.calculate_tef("CVE-2026-12345")
        self.assertEqual(0.01, result["epss"])
        self.assertAlmostEqual(1 - 0.99 ** (365 / 30), result["epss_annual"], places=6)
        self.assertEqual(round(result["epss_annual"] * 0.8, 3), result["mode"])

    def test_exposes_three_component_breakdown(self):
        tef = {"min": 0.1, "mode": 0.2, "max": 0.3}
        pressure = {
            "cve_id": "CVE-2026-67276", "status": "assessed",
            "tef_adjustment": {
                "method": "multiply", "factor": 1.2,
                "components": {"region": 1.0, "sector": 1.0, "cve": 1.4},
                "weights": {"region": 0.25, "sector": 0.25, "cve": 0.5},
            },
        }
        result = apply_tef_adjustment(tef, pressure, "CVE-2026-67276")
        self.assertEqual(1.2, result["pressure_factor"])
        self.assertEqual(1.4, result["pressure_components"]["cve"])
        self.assertEqual(0.5, result["pressure_weights"]["cve"])

    def test_rejects_mismatch_or_unbounded_multiplier(self):
        tef = {"min": 0.1, "mode": 0.2, "max": 0.3}
        pressure = {"cve_id": "CVE-2026-12345", "status": "assessed",
                    "tef_adjustment": {"method": "multiply", "factor": 1.2}}
        with self.assertRaises(ValueError):
            apply_tef_adjustment(tef, pressure, "CVE-2026-99999")
        pressure["tef_adjustment"]["factor"] = 2.0
        with self.assertRaises(ValueError):
            apply_tef_adjustment(tef, pressure, "CVE-2026-12345")

    def test_neutral_assessment_keeps_tef_and_uplift_is_clipped(self):
        tef = {"min": 0.8, "mode": 0.9, "max": 0.98, "epss": 0.9}
        pressure = {"cve_id": "CVE-2026-12345", "status": "insufficient_data",
                    "tef_adjustment": {"method": "multiply", "factor": 1.0}}
        neutral = apply_tef_adjustment(tef, pressure, "CVE-2026-12345")
        self.assertEqual(0.9, neutral["mode"])
        pressure["status"] = "assessed"
        pressure["tef_adjustment"]["factor"] = 1.2
        adjusted = apply_tef_adjustment(tef, pressure, "CVE-2026-12345")
        self.assertEqual(1.0, adjusted["mode"])
        self.assertEqual(1.0, adjusted["max"])
        self.assertEqual(0.9, adjusted["epss"])


if __name__ == "__main__":
    unittest.main()
