import requests
import time
import mysql.connector
import pandas as pd
from typing import Optional, Dict, Any
from urllib.parse import urlparse

class VirusTotalAPI:
    def __init__(self):
        self.API_KEY = 'fa5b45f78251ca5fa46f741048b99ae4b92df6e26878352543c9c2ab95ac0994'
        self.BASE_URL = 'https://www.virustotal.com/api/v3'
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.API_KEY
        }
        # Load the malicious URLs dataset
        try:
            self.malicious_urls_df = pd.read_csv('malicious_phish.csv')
        except Exception as e:
            print(f"Error loading dataset: {e}")
            self.malicious_urls_df = None

    def connect_db(self) -> mysql.connector.connection.MySQLConnection:
        """Create and return database connection"""
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="Dhruv001@",
            database="cybersecurity_db"
        )

    def store_threat_indicator(self, user_id: int, url: str, malicious: int, suspicious: int, harmless: int, severity: int) -> None:
        """Store threat information in the database"""
        conn = self.connect_db()
        cursor = conn.cursor()
        
        try:
            query = """
                INSERT INTO threat_indicator 
                (user_id, website_url, malicious_detections, suspicious_detections, 
                 harmless_detections, severity_level, scan_date) 
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """
            cursor.execute(query, (
                user_id,
                url,
                malicious,
                suspicious,
                harmless,
                severity
            ))
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    def submit_url_for_scanning(self, url: str) -> Optional[str]:
        """Submit URL to VirusTotal for scanning"""
        try:
            scan_params = {"url": url}
            response = requests.post(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                data=scan_params
            )
            
            if response.status_code == 200:
                return response.json()['data']['id']
            else:
                print(f"Error submitting URL: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error in submit_url_for_scanning: {e}")
            return None

    def get_analysis_results(self, analysis_id: str) -> Optional[Dict]:
        """Get analysis results from VirusTotal"""
        try:
            analysis_url = f"{self.BASE_URL}/analyses/{analysis_id}"
            response = requests.get(analysis_url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error getting analysis: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error in get_analysis_results: {e}")
            return None

    def calculate_severity(self, stats: Dict[str, int]) -> int:
        """Calculate severity score based on scan results"""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total_scanners = sum(stats.values())
        
        if total_scanners > 0:
            return int((malicious + suspicious) / total_scanners * 10)
        return 0

    def check_local_database(self, url: str) -> Dict[str, Any]:
        """Check URL against local malicious URL database"""
        if self.malicious_urls_df is not None:
            # Extract domain from URL
            try:
                domain = urlparse(url).netloc
                if not domain:
                    domain = urlparse(f"http://{url}").netloc

                # Check if domain exists in dataset
                matches = self.malicious_urls_df[
                    self.malicious_urls_df['url'].str.contains(domain, case=False, na=False)
                ]

                if not matches.empty:
                    # Get the type and details of the threat
                    threat_type = matches.iloc[0].get('type', 'unknown')
                    return {
                        'is_malicious': True,
                        'threat_type': threat_type,
                        'confidence': 'high',
                        'source': 'local_database'
                    }
            except Exception as e:
                print(f"Error checking local database: {e}")

        return {'is_malicious': False}

    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """Analyze URL structure for suspicious patterns"""
        suspicious_patterns = {
            'defacement': [
                'index.php?option=com_content',
                'index.php?option=com',
                'vsig',
                'view=article'
            ],
            'phishing': [
                'login',
                'signin',
                'account',
                'verify',
                'secure',
                'update'
            ]
        }

        results = {
            'suspicious_patterns_found': [],
            'risk_score': 0
        }

        url_lower = url.lower()
        
        # Check for suspicious patterns
        for threat_type, patterns in suspicious_patterns.items():
            for pattern in patterns:
                if pattern in url_lower:
                    results['suspicious_patterns_found'].append({
                        'pattern': pattern,
                        'type': threat_type
                    })
                    results['risk_score'] += 2  # Increment risk score for each pattern

        return results

    def scan_url(self, url: str, user_id: int) -> Optional[Dict]:
        """Enhanced URL scanning with multiple detection methods"""
        try:
            # First check local database
            local_check = self.check_local_database(url)
            
            # Analyze URL structure
            structure_analysis = self.analyze_url_structure(url)
            
            # Initialize base threat scores
            malicious_score = 0
            suspicious_score = 0
            
            # Adjust scores based on local database check
            if local_check['is_malicious']:
                malicious_score += 10
                
            # Adjust scores based on URL structure analysis
            if structure_analysis['suspicious_patterns_found']:
                suspicious_score += len(structure_analysis['suspicious_patterns_found']) * 2
                if any(p['type'] == 'defacement' for p in structure_analysis['suspicious_patterns_found']):
                    malicious_score += 5

            # Proceed with VirusTotal scan
            analysis_id = self.submit_url_for_scanning(url)
            if analysis_id:
                time.sleep(3)  # Wait for analysis
                vt_results = self.get_analysis_results(analysis_id)
                
                if vt_results:
                    stats = vt_results['data']['attributes']['stats']
                    malicious_score += stats.get('malicious', 0) * 2
                    suspicious_score += stats.get('suspicious', 0)
                    harmless = stats.get('harmless', 0)
                    
                    # Calculate final severity (0-10 scale)
                    total_score = malicious_score + suspicious_score
                    severity = min(10, int(total_score / 3))  # Normalize to 0-10 scale
                    
                    return {
                        'malicious': malicious_score,
                        'suspicious': suspicious_score,
                        'harmless': harmless,
                        'severity': severity,
                        'patterns_detected': structure_analysis['suspicious_patterns_found'],
                        'local_database_match': local_check['is_malicious']
                    }

            # Return results even if VirusTotal scan fails
            severity = min(10, int((malicious_score + suspicious_score) / 3))
            return {
                'malicious': malicious_score,
                'suspicious': suspicious_score,
                'harmless': 0,
                'severity': severity,
                'patterns_detected': structure_analysis['suspicious_patterns_found'],
                'local_database_match': local_check['is_malicious']
            }

        except Exception as e:
            print(f"Error in scan_url: {e}")
            return None

def get_api_instance() -> VirusTotalAPI:
    """Factory function to create API instance"""
    return VirusTotalAPI()
