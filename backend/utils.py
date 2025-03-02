import re
import json
import datetime
import ipaddress
import numpy as np
import requests
from typing import Dict, List, Optional, Union, Any
import os
import tensorflow as tf
import google.generativeai as genai  # Add Google import
from config import GOOGLE_API_KEY, CVE_API_URL, MITRE_ATTACK_URL

# Configure Google API instead of OpenAI
genai.configure(api_key=GOOGLE_API_KEY)

class LogParser:
    """Class for parsing security logs from various sources"""
    
    def __init__(self, templates: Optional[List[Dict]] = None):
        """Initialize parser with optional templates
        
        Args:
            templates: List of log templates with regex patterns and field mappings
        """
        self.templates = templates or []
        
    def add_template(self, source_type: str, regex_pattern: str, field_mapping: Dict, description: str):
        """Add a new log template
        
        Args:
            source_type: The log source (e.g., 'fortinet', 'linux_syslog')
            regex_pattern: Regular expression pattern to match the log
            field_mapping: Dictionary mapping regex groups to field names
            description: Human-readable description of the template
        """
        self.templates.append({
            'source_type': source_type,
            'regex_pattern': regex_pattern,
            'field_mapping': field_mapping,
            'description': description
        })
        
    def parse_log(self, log_line: str, source_type: Optional[str] = None) -> Optional[Dict]:
        """Parse a log line using templates
        
        Args:
            log_line: Raw log line to parse
            source_type: Optional source type to filter templates
            
        Returns:
            Dictionary with parsed fields or None if no template matches
        """
        templates_to_try = [t for t in self.templates if source_type is None or t['source_type'] == source_type]
        
        for template in templates_to_try:
            pattern = template['regex_pattern']
            field_mapping = template['field_mapping']
            
            match = re.match(pattern, log_line)
            if match:
                result = {'raw_log': log_line, 'source_type': template['source_type']}
                for field_name, group_name in field_mapping.items():
                    try:
                        result[field_name] = match.group(group_name)
                    except IndexError:
                        result[field_name] = None
                return result
                
        return None
    
    def normalize_ip(self, ip_str: str) -> Optional[str]:
        """Normalize IP address strings to standard format
        
        Args:
            ip_str: IP address string
            
        Returns:
            Normalized IP string or None if invalid
        """
        try:
            return str(ipaddress.ip_address(ip_str.strip()))
        except ValueError:
            return None

    def extract_severity(self, parsed_log: Dict) -> float:
        """Extract or calculate severity from parsed log
        
        Args:
            parsed_log: Dictionary with parsed log fields
            
        Returns:
            Severity score (0.0-1.0)
        """
        # Look for severity fields based on log source
        if parsed_log['source_type'] == 'fortinet':
            if 'level' in parsed_log:
                # Map Fortinet severity levels to scores
                level_map = {
                    'emergency': 1.0,
                    'alert': 0.9,
                    'critical': 0.8,
                    'error': 0.7,
                    'warning': 0.5,
                    'notice': 0.3,
                    'information': 0.2,
                    'debug': 0.1
                }
                return level_map.get(parsed_log['level'].lower(), 0.5)
        
        # Default severity calculation based on keywords
        severity_keywords = {
            'critical': 0.9,
            'alert': 0.85,
            'emergency': 0.95,
            'error': 0.7,
            'fail': 0.65,
            'warning': 0.5,
            'denied': 0.6,
            'blocked': 0.55
        }
        
        # Calculate severity based on keywords in the raw log
        raw_log = parsed_log.get('raw_log', '').lower()
        max_severity = 0.1  # Default low severity
        
        for keyword, value in severity_keywords.items():
            if keyword in raw_log:
                max_severity = max(max_severity, value)
        
        return max_severity

class VectorEmbeddings:
    """Class for generating and managing vector embeddings"""
    
    def __init__(self, use_google: bool = True):
        """Initialize embeddings generator
        
        Args:
            use_google: Whether to use Google embeddings (True) or local model (False)
        """
        self.use_google = use_google
        if use_google:
            import google.generativeai as genai
            from config import GOOGLE_API_KEY
            genai.configure(api_key=GOOGLE_API_KEY)
            # Don't store a reference to a method that doesn't exist
        else:
            # Load local embedding model - you would need to have this saved
            self.model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "embeddings")
            if os.path.exists(self.model_path):
                self.model = tf.saved_model.load(self.model_path)
            else:
                raise ValueError(f"Local embedding model not found at {self.model_path}")
    
    def get_embedding(self, text: str) -> List[float]:
        """Generate embedding for text
        
        Args:
            text: Text to generate embedding for
            
        Returns:
            List of embedding values
        """
        if self.use_google:
            # Use Google's embed_content function correctly
            result = genai.embed_content(
                model="models/embedding-001",  # Add the 'models/' prefix
                content=text,
                task_type="retrieval_document"
            )
            # Extract the embedding vector
            embedding = result["embedding"]
        else:
            # Use local model
            result = self.model([text])
            embedding = result[0].numpy().tolist()
        
        # Ensure the embedding is 768 dimensions (not 1536)
        if len(embedding) > 768:
            # Truncate to 768
            embedding = embedding[:768]
        elif len(embedding) < 768:
            # Pad to 768
            padding = [0.0] * (768 - len(embedding))
            embedding = embedding + padding
        
        return embedding
    
    def get_batch_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts"""
        if self.use_google:
            # Process each text individually
            embeddings = []
            for text in texts:
                result = genai.embed_content(
                    model="models/embedding-001",
                    content=text,
                    task_type="retrieval_document"
                )
                embedding = result["embedding"]
                # Ensure the embedding is 768 dimensions (not 1536)
                if len(embedding) > 768:
                    # Truncate to 768
                    embedding = embedding[:768]
                elif len(embedding) < 768:
                    # Pad to 768
                    padding = [0.0] * (768 - len(embedding))
                    embedding = embedding + padding
                embeddings.append(embedding)
            return embeddings
        else:
            # Use local model in batch mode
            results = []
            for text in texts:
                result = self.model([text])
                embedding = result[0].numpy().tolist()
                # Ensure the embedding is 1536 dimensions
                if len(embedding) < 1536:
                    # Pad embedding to 1536 dimensions
                    padding = [0.0] * (1536 - len(embedding))
                    embedding = embedding + padding
                results.append(embedding)
            return results

class ThreatIntelligenceFetcher:
    """Class for fetching threat intelligence from external sources"""
    
    def __init__(self):
        """Initialize the threat intelligence fetcher"""
        pass
    
    def fetch_cve(self, cve_id: Optional[str] = None, 
                 keywords: Optional[List[str]] = None,
                 max_results: int = 10) -> List[Dict]:
        """Fetch CVE data from NVD
        
        Args:
            cve_id: Specific CVE ID to fetch
            keywords: Keywords to search for
            max_results: Maximum number of results to return
            
        Returns:
            List of CVE records
        """
        params = {}
        if cve_id:
            params['cveId'] = cve_id
        elif keywords:
            params['keyword'] = ' '.join(keywords)
        
        params['resultsPerPage'] = max_results
        
        try:
            response = requests.get(CVE_API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            results = []
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                cve_metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                
                # Extract CVSS score
                base_score = cve_metrics.get('baseScore', 0)
                
                # Format and add to results
                results.append({
                    'source': 'CVE',
                    'reference_id': cve.get('id', ''),
                    'title': cve.get('descriptions', [{}])[0].get('value', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                    'severity': base_score,
                    'published_date': cve.get('published', ''),
                    'updated_date': cve.get('lastModified', '')
                })
            
            return results
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
            return []
    
    def fetch_mitre_attack(self, technique_id: Optional[str] = None) -> List[Dict]:
        """Fetch MITRE ATT&CK data
        
        Args:
            technique_id: Specific technique ID to fetch
            
        Returns:
            List of technique records
        """
        # This would need to be expanded to properly scrape or use MITRE's API
        # For now, returning a sample implementation
        if technique_id:
            url = f"{MITRE_ATTACK_URL}/{technique_id}"
        else:
            url = MITRE_ATTACK_URL
            
        # In a real implementation, you would fetch and parse the data from MITRE
        # This is a placeholder
        return [{
            'source': 'MITRE_ATTACK',
            'reference_id': 'T1110',
            'title': 'Brute Force',
            'description': 'Adversaries may use brute force techniques to gain access to accounts.',
            'severity': 0.7,
            'published_date': '2020-10-01',
            'updated_date': '2021-04-15'
        }]
