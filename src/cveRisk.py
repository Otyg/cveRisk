# Example usage

from cveTef import TEFCalculator


if __name__ == "__main__":
    calculator = TEFCalculator()
    
    # Load data once
    calculator.load_data()
    
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
        result = calculator.calculate_tef(cve)
        print(f"\n{cve}:")
        print(f"  EPSS Score:     {result['epss']} (Percentile: {result['percentile']})")
        print(f"  In CISA KEV:    {result['in_cisa_kev']}")
        print(f"  TEF - Min: {result['min']}, Mode: {result['mode']}, Max: {result['max']}")