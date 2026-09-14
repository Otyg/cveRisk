"""Example TEF calculation with FeedSummary attack-pressure context."""

import requests
import statistics
import numpy as np
import plotext as plt
from otyg_risk_base.montecarlo import MonteCarloRange, MonteCarloSimulation

from cveTef import TEFCalculator


PRESSURE_URL = "http://localhost:5001/api/v1/long-term/attack-pressure"
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
    total_tef = MonteCarloRange()
    max_tef = list()
    mode_tef = list()
    min_tef = list()

    with open('cve.txt', 'r') as file:
        test_cves = [line.strip() for line in file if line.strip()]

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
        max_tef.append(result['max'])
        mode_tef.append(result['mode'])
        min_tef.append(result['min'])
        print(f"\n{cve}:")
        print(f"  EPSS (30 days): {result['epss']} (Percentile: {result['percentile']})")
        print(f"  EPSS (365-day extrapolation): {result['epss_annual']}")
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
    total_tef = MonteCarloSimulation(MonteCarloRange(min=min(min_tef), probable=statistics.mode(mode_tef), max=max(max_tef)))
    print(f"  Total TEF - Min: {round(total_tef.min, 3)}, probable: {round(total_tef.probable, 3)}, p90: {round(total_tef.p90, 3)}, Max: {round(total_tef.max, 3)}")
    fig = plt.figure
    fig.clear()
    fig.draw(fig.hist(total_tef._MonteCarloSimulation__samples, bins=100))
    
    fig.title("Frekvenshistogram")
    fig.xlabel("Resultat")
    fig.ylabel("Antal")
    fig.show()

if __name__ == "__main__":
    main()
