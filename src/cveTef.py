import requests
import gzip
import csv
import io
import math
from typing import Dict, Optional, Tuple
from otyg_risk_base.montecarlo import MonteCarloRange, MonteCarloSimulation


EPSS_WINDOW_DAYS = 30
TEF_HORIZON_DAYS = 365


def annualize_epss(epss_30d: float) -> float:
    """Extrapolate a 30-day probability under a constant exploitation hazard.

    EPSS itself predicts only the next 30 days. This is a planning assumption,
    not a separately calibrated one-year EPSS forecast.
    """
    probability = float(epss_30d)
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError('EPSS probability must be between 0 and 1')
    if probability in (0.0, 1.0):
        return probability
    return -math.expm1(
        (TEF_HORIZON_DAYS / EPSS_WINDOW_DAYS) * math.log1p(-probability)
    )


def apply_tef_adjustment(tef: Dict, pressure: Dict, cve_id: str) -> Dict:
    """Apply a matching FeedSummary attack-pressure response to a TEF result.

    The pressure API provides a bounded multiplier, not an EPSS replacement.
    Unknown or stale assessments carry a neutral factor of 1.0.
    """
    if str(pressure.get('cve_id') or '').upper() != str(cve_id).upper():
        raise ValueError('attack-pressure CVE does not match TEF CVE')
    adjustment = pressure.get('tef_adjustment') or {}
    if adjustment.get('method') != 'multiply':
        raise ValueError('unsupported TEF adjustment method')
    factor = float(adjustment.get('factor', 1.0))
    if not 1.0 <= factor <= 1.3:
        raise ValueError('TEF adjustment factor must be between 1.0 and 1.3')
    if pressure.get('status') != 'assessed' and factor != 1.0:
        raise ValueError('unassessed pressure must have a neutral factor')
    result = dict(tef)
    for key in ('min', 'mode', 'max'):
        result[key] = round(min(1.0, float(tef[key]) * factor), 3)
    result['pressure_factor'] = factor
    result['pressure_report_id'] = (pressure.get('evidence') or {}).get('report_id')
    if isinstance(adjustment.get('components'), dict):
        result['pressure_components'] = dict(adjustment['components'])
    if isinstance(adjustment.get('weights'), dict):
        result['pressure_weights'] = dict(adjustment['weights'])
    return result

class TEFCalculator:
    """
    Calculate Threat Event Frequency using EPSS and CISA KEV data.
    
    TEF represents the expected frequency of exploitation as (min, max, mode)
    normalized to a 0-1 scale.
    """
    
    def __init__(self):
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.epss_csv_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
        self.cisa_kev_data = None
        self.epss_data = None  # Dict mapping CVE -> {'epss': float, 'percentile': float}
        self.load_data()
    
    def fetch_epss_scores(self) -> Dict[str, Dict[str, float]]:
        """
        Fetch and parse the EPSS gzipped CSV.
        
        Returns:
            Dictionary mapping CVE ID -> {'epss': score, 'percentile': percentile}
        """
        try:
            print("Fetching EPSS data...")
            response = requests.get(self.epss_csv_url, timeout=30)
            response.raise_for_status()
            
            # Decompress gzip content
            decompressed = gzip.decompress(response.content)
            
            # Parse CSV
            csv_reader = csv.DictReader(
                io.StringIO(decompressed.decode('utf-8')),
                fieldnames=['CVE', 'epss', 'percentile']
            )
            
            epss_dict = {}
            for row in csv_reader:
                if row['CVE'] and row['CVE'].upper().startswith('CVE-'):
                    try:
                        epss_dict[row['CVE'].upper()] = {
                            'epss': float(row['epss']),
                            'percentile': float(row['percentile'])
                        }
                    except (ValueError, KeyError):
                        continue
            
            self.epss_data = epss_dict
            print(f"Loaded {len(epss_dict)} EPSS records")
            return epss_dict
        
        except requests.RequestException as e:
            print(f"Error fetching EPSS CSV: {e}")
            self.epss_data = {}
            return {}
    
    def fetch_cisa_kev(self) -> Dict:
        """Fetch the CISA KEV catalog."""
        try:
            print("Fetching CISA KEV data...")
            response = requests.get(self.cisa_kev_url, timeout=10)
            response.raise_for_status()
            self.cisa_kev_data = response.json()
            print(f"Loaded {len(self.cisa_kev_data.get('vulnerabilities', []))} KEV records")
            return self.cisa_kev_data
        except requests.RequestException as e:
            print(f"Error fetching CISA KEV: {e}")
            return {}
    
    def load_data(self):
        """Load both EPSS and CISA KEV data."""
        self.fetch_epss_scores()
        self.fetch_cisa_kev()
    
    def is_in_cisa_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV catalog."""
        if not self.cisa_kev_data:
            self.fetch_cisa_kev()
        
        if not self.cisa_kev_data or 'vulnerabilities' not in self.cisa_kev_data:
            return False
        
        cve_id_upper = cve_id.upper()
        return any(
            vuln.get('cveID', '').upper() == cve_id_upper 
            for vuln in self.cisa_kev_data['vulnerabilities']
        )
    
    def get_epss_score(self, cve_id: str) -> Optional[Tuple[float, float]]:
        """
        Get EPSS score and percentile from loaded data.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
        
        Returns:
            Tuple of (epss_score, percentile) or None if not found
        """
        if not self.epss_data:
            self.fetch_epss_scores()
        
        cve_upper = cve_id.upper()
        if cve_upper in self.epss_data:
            data = self.epss_data[cve_upper]
            return (data['epss'], data['percentile'])
        
        return None
    
    def calculate_tef(self, cve_id: str, pressure: Optional[Dict] = None) -> Dict[str, float]:
        """
        Calculate Threat Event Frequency (min, max, mode).
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
        
        Returns:
            Annual-horizon TEF and annualized EPSS, alongside the original
            30-day EPSS probability, percentile and CISA KEV indicator.
        """
        # Get EPSS data
        epss_result = self.get_epss_score(cve_id)
        
        if epss_result is None:
            epss_score = 0.0
            percentile = 0.0
        else:
            epss_score, percentile = epss_result

        epss_annual = annualize_epss(epss_score)
        
        # Check if in CISA KEV
        in_kev = self.is_in_cisa_kev(cve_id)
        
        # TEF calculation using the extrapolated annual probability.
        if in_kev:
            # Known exploited vulnerabilities have higher baseline frequency
            # Mode is closer to the EPSS score (already being exploited)
            mode = epss_annual
            
            # Min: assumes at least some exploitation activity
            min_tef = max(0.1, epss_annual * 0.7)
            
            # Max: can spike with active campaigns
            max_tef = min(1.0, epss_annual + 0.2)
        else:
            # Non-KEV vulnerabilities: lower baseline
            mode = epss_annual * 0.8
            
            # Min: low but possible exploitation
            min_tef = epss_annual * 0.4
            
            # Max: potential if exploited in future
            max_tef = min(0.9, epss_annual + 0.15)
        range = MonteCarloRange(min=min_tef, max=max_tef, probable=mode)
        result = {
            'min': round(range.min, 3),
            'max': round(range.max, 3),
            'mode': round(range.probable, 3),
            'epss': round(epss_score, 6),
            'epss_annual': round(epss_annual, 6),
            'epss_horizon_days': EPSS_WINDOW_DAYS,
            'tef_horizon_days': TEF_HORIZON_DAYS,
            'annualization_model': 'constant_30_day_hazard',
            'percentile': round(percentile, 3),
            'in_cisa_kev': in_kev
        }
        return apply_tef_adjustment(result, pressure, cve_id) if pressure is not None else result
