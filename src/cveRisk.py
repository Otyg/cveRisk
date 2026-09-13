"""Example TEF calculation with FeedSummary attack-pressure context."""

import requests

from cveTef import TEFCalculator


PRESSURE_URL = "https://otyg.freeddns.org:8443/api/v1/long-term/attack-pressure"
LONG_TERM_PROFILE = "healthcare_europe"


def fetch_attack_pressure(cve_id: str) -> dict:
    """Fetch the current region, sector and CVE pressure assessment."""

    response = requests.get(
        PRESSURE_URL,
        params={"profile": LONG_TERM_PROFILE, "cve": cve_id},
        timeout=10,
    )
    response.raise_for_status()
    pressure = response.json()
    if not isinstance(pressure, dict):
        raise ValueError("attack-pressure response must be a JSON object")
    return pressure


def main() -> None:
    calculator = TEFCalculator()

    # Example CVEs
    test_cves = [
        "CVE-2026-87995",
        "CVE-2026-20316",
        "CVE-2026-85103",
    ]

    print("\n" + "="*70)
    print("Threat Event Frequency Calculation")
    print("="*70)

    for cve in test_cves:
        try:
            pressure = fetch_attack_pressure(cve)
        except (requests.RequestException, ValueError) as exc:
            print(f"  Attack pressure unavailable for {cve}: {exc}")
            pressure = None

        try:
            result = calculator.calculate_tef(cve, pressure=pressure)
        except ValueError as exc:
            if pressure is None:
                raise
            print(f"  Invalid attack pressure for {cve}: {exc}")
            result = calculator.calculate_tef(cve)

        print(f"\n{cve}:")
        print(f"  EPSS (30 days): {result['epss']} (Percentile: {result['percentile']})")
        print(f"  EPSS (365-day extrapolation): {result['epss_annual']}")
        print(f"  In CISA KEV:    {result['in_cisa_kev']}")
        print(f"  TEF - Min: {result['min']}, Mode: {result['mode']}, Max: {result['max']}")
        if "pressure_factor" in result:
            print(f"  Pressure factor: {result['pressure_factor']}")
            components = result.get("pressure_components") or {}
            if components:
                print(
                    "  Components - "
                    f"Region: {components.get('region')}, "
                    f"Sector: {components.get('sector')}, "
                    f"CVE: {components.get('cve')}"
                )


if __name__ == "__main__":
    main()
