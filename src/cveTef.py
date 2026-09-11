import requests
import gzip
import csv
import io
from typing import Dict, Optional, Tuple

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
    
    def calculate_tef(self, cve_id: str) -> Dict[str, float]:
        """
        Calculate Threat Event Frequency (min, max, mode).
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
        
        Returns:
            Dictionary with 'min', 'max', 'mode', 'epss', 'percentile', 'in_cisa_kev' keys
        """
        # Get EPSS data
        epss_result = self.get_epss_score(cve_id)
        
        if epss_result is None:
            epss_score = 0.0
            percentile = 0.0
        else:
            epss_score, percentile = epss_result
        
        # Check if in CISA KEV
        in_kev = self.is_in_cisa_kev(cve_id)
        
        # TEF calculation using EPSS
        if in_kev:
            # Known exploited vulnerabilities have higher baseline frequency
            # Mode is closer to the EPSS score (already being exploited)
            mode = epss_score
            
            # Min: assumes at least some exploitation activity
            min_tef = max(0.1, epss_score * 0.7)
            
            # Max: can spike with active campaigns
            max_tef = min(1.0, epss_score + 0.2)
        else:
            # Non-KEV vulnerabilities: lower baseline
            mode = epss_score * 0.8
            
            # Min: low but possible exploitation
            min_tef = epss_score * 0.4
            
            # Max: potential if exploited in future
            max_tef = min(0.9, epss_score + 0.15)
        
        return {
            'min': round(min_tef, 3),
            'max': round(max_tef, 3),
            'mode': round(mode, 3),
            'epss': round(epss_score, 3),
            'percentile': round(percentile, 3),
            'in_cisa_kev': in_kev
        }
