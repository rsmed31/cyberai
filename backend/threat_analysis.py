import os
import json
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
# import openai  # Comment out or remove
import google.generativeai as genai  # Add Google's API
from sqlalchemy.orm import Session
from sqlalchemy import text
import tensorflow as tf
import time
import datetime
import ipaddress

from config import GOOGLE_API_KEY, ALERT_THRESHOLD
from models import ThreatIntelligence, SecurityIncident, IncidentThreatRelation, RecommendedAction
from utils import LogParser, VectorEmbeddings, ThreatIntelligenceFetcher

# Configure Google Generative AI
genai.configure(api_key=GOOGLE_API_KEY)

class ThreatAnalyzer:
    """Core class for analyzing security incidents using LLMs and RAG"""
    
    def __init__(self, db_session: Session, use_google: bool = True, use_tensorflow: bool = False):
        """Initialize the threat analyzer
        
        Args:
            db_session: Database session
            use_google: Whether to use Google API for LLM analysis
            use_tensorflow: Whether to use local TensorFlow model
        """
        self.db = db_session
        self.use_google = use_google
        self.use_tensorflow = use_tensorflow
        self.embeddings = VectorEmbeddings(use_google=use_google)
        self.log_parser = LogParser()
        self.threat_fetcher = ThreatIntelligenceFetcher()
        
        # Load Google models
        if use_google:
            self.generation_model = genai.GenerativeModel('gemini-1.5-flash')
            self.embedding_model = genai.GenerativeModel('models/embedding-001')
        
        # Load local TensorFlow model if configured
        if use_tensorflow:
            model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "threat_analyzer")
            if os.path.exists(model_path):
                self.tf_model = tf.saved_model.load(model_path)
            else:
                self.use_tensorflow = False
                print(f"Warning: TensorFlow model not found at {model_path}, falling back to Google API")
        
        # Load log templates
        self._load_log_templates()
    
    def _load_log_templates(self):
        """Load log templates from database or add defaults"""
        # Add default templates for common log formats
        
        # Fortinet firewall log template - standard pattern
        self.log_parser.add_template(
            source_type="fortinet",
            regex_pattern=r'date=(?P<date>[^ ]+) time=(?P<time>[^ ]+) .*?level=(?P<level>[^ ]+) .*?srcip=(?P<srcip>[^ ]+) srcport=(?P<srcport>[^ ]+) dstip=(?P<dstip>[^ ]+) dstport=(?P<dstport>[^ ]+) .*?action=(?P<action>[^ ]+)',
            field_mapping={
                "date": "date",
                "time": "time",
                "level": "level",
                "source_ip": "srcip",
                "source_port": "srcport",
                "destination_ip": "dstip",
                "destination_port": "dstport",
                "action": "action"
            },
            description="Fortinet FortiGate firewall logs"
        )
        
        # Add a simplified Fortinet log template for testing
        self.log_parser.add_template(
            source_type="fortinet",
            regex_pattern=r'date=(?P<date>[^ ]+) time=(?P<time>[^ ]+) .*?level=(?P<level>[^ ]+).*?srcip=(?P<srcip>[^ ]+).*?dstip=(?P<dstip>[^ ]+).*?action=(?P<action>[^ ]+)',
            field_mapping={
                "date": "date",
                "time": "time",
                "level": "level",
                "source_ip": "srcip",
                "destination_ip": "dstip",
                "action": "action"
            },
            description="Simplified Fortinet FortiGate firewall logs (for testing)"
        )
        
        # Linux syslog SSH template
        self.log_parser.add_template(
            source_type="linux_syslog",
            regex_pattern=r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>[^ ]+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)',
            field_mapping={
                "date": "date",
                "hostname": "hostname",
                "pid": "pid",
                "message": "message"
            },
            description="Linux syslog SSH login attempts"
        )
        
        # Azure WAF log template
        self.log_parser.add_template(
            source_type="azure_waf",
            regex_pattern=r'.*clientIP=(?P<clientip>[^ ]+).*resourceId=(?P<resourceid>[^ ]+).*requestUri="(?P<uri>[^"]+)".*ruleId=(?P<ruleid>[^ ]+).*action=(?P<action>[^ ]+)',
            field_mapping={
                "client_ip": "clientip",
                "resource_id": "resourceid",
                "request_uri": "uri",
                "rule_id": "ruleid",
                "action": "action"
            },
            description="Azure WAF logs"
        )
    
    def analyze_log(self, log_line: str, source_type: Optional[str] = None) -> Dict:
        """Analyze a single log line and return findings
        
        Args:
            log_line: Raw log line to analyze
            source_type: Optional source type to assist the parser
            
        Returns:
            Dictionary with analysis results including parsed log, severity, 
            related threats, and recommendations
        """
        # Parse the log
        parsed_log = self.log_parser.parse_log(log_line, source_type)
        if not parsed_log:
            return {
                "success": False,
                "error": "Failed to parse log",
                "raw_log": log_line
            }
        
        # Add the raw log to the parsed result
        parsed_log["raw_log"] = log_line
        
        # Extract potential indicators of compromise from the log
        iocs = self._extract_iocs(parsed_log)
        
        # Create an incident record in the database for significant findings
        incident = None
        severity = self.log_parser.extract_severity(parsed_log)
        if severity >= ALERT_THRESHOLD:
            # Create security incident
            incident = SecurityIncident(
                source_ip=parsed_log.get("source_ip", "unknown"),
                destination_ip=parsed_log.get("destination_ip", "unknown"),
                log_source=parsed_log.get("source_type", source_type or "unknown"),
                severity=severity,
                description=self._generate_incident_description(parsed_log),
                raw_log=log_line
            )
            self.db.add(incident)
            self.db.commit()
            self.db.refresh(incident)
        
        # Find related threats using the parsed data
        related_threats = []
        if incident:
            related_threats = self._find_related_threats(parsed_log, incident.id)
        else:
            # Even if we didn't create an incident, still look for threats
            related_threats = self._find_related_threats(parsed_log, None)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(parsed_log, related_threats)
        
        # Find related IOCs in threat intelligence
        related_iocs = self._find_related_iocs(iocs)
        
        return {
            "success": True,
            "parsed_log": parsed_log,
            "severity": severity,
            "related_threats": related_threats,
            "recommendations": recommendations,
            "incident_id": incident.id if incident else None,
            "iocs": iocs,
            "related_intelligence": related_iocs
        }
    
    def analyze_logs(self, logs: List[str], source_type: Optional[str] = None) -> List[Dict]:
        """Analyze multiple logs
        
        Args:
            logs: List of raw log lines
            source_type: Optional log source type
            
        Returns:
            List of analysis results
        """
        results = []
        for log in logs:
            result = self.analyze_log(log, source_type)
            results.append(result)
        return results
    
    def _find_related_threats(self, parsed_log: Dict, incident_id: int) -> List[Dict]:
        """Find threats related to the log using vector similarity"""
        # Create a query for vector similarity search
        log_text = f"{parsed_log.get('source_type', '')} {parsed_log.get('raw_log', '')}"
        log_embedding = self.embeddings.get_embedding(log_text)
        
        # Format vector as string with raw SQL to avoid parameter binding issues
        vector_values = ', '.join(str(val) for val in log_embedding)
        raw_query = f"""
            SELECT 
                id, source, reference_id, title, description, severity,
                1 - (embedding <=> '[{vector_values}]'::vector) as similarity
            FROM 
                threat_intelligence
            WHERE 
                1 - (embedding <=> '[{vector_values}]'::vector) > {ALERT_THRESHOLD}
            ORDER BY 
                similarity DESC
            LIMIT 5
        """
        query = text(raw_query)
        
        # Execute without parameters since they're directly in the query
        result = self.db.execute(query)
        
        related_threats = []
        for row in result:
            threat_id = row[0]
            similarity = float(row[6])
            
            # Add to the relation table
            relation = IncidentThreatRelation(
                incident_id=incident_id,
                threat_id=threat_id,
                confidence=similarity
            )
            self.db.add(relation)
            
            # Add to results
            threat_info = {
                "id": threat_id,
                "source": row[1],
                "reference_id": row[2],
                "title": row[3],
                "description": row[4],
                "severity": float(row[5]),
                "similarity": similarity
            }
            related_threats.append(threat_info)
        
        return related_threats
    
    def _generate_recommendations(self, parsed_log: Dict, related_threats: List[Dict]) -> List[Dict]:
        """Generate recommendations using LLM based on the log and related threats
        
        Args:
            parsed_log: Dictionary with parsed log fields
            related_threats: List of related threats
            
        Returns:
            List of recommendation dictionaries
        """
        if self.use_tensorflow:
            # Use local TensorFlow model for recommendations
            # This would need to be implemented based on your specific model
            pass
        
        if self.use_google:
            # Use Google API for recommendations
            threats_text = "\n".join([
                f"Threat {i+1}: {threat['title']} ({threat['reference_id']})" +
                f"\nDescription: {threat['description']}" +
                f"\nSeverity: {threat['severity']}"
                for i, threat in enumerate(related_threats)
            ])
            
            prompt = f"""
            Analyze the following security log and related threats, then provide detailed recommendations for responding to this security incident:
            
            LOG SOURCE: {parsed_log.get('source_type', 'Unknown')}
            RAW LOG: {parsed_log.get('raw_log', '')}
            
            PARSED INFORMATION:
            {json.dumps(parsed_log, indent=2)}
            
            RELATED THREATS:
            {threats_text}
            
            Provide 2-3 specific recommendations for responding to this incident. For each recommendation, include:
            1. The type of action (e.g., "firewall_rule", "system_update", "investigation")
            2. A detailed description of what should be done
            3. Priority level (1-5, with 1 being highest)
            
            Format your response as a JSON array of recommendations.
            """
            
            try:
                # Use Google's Generative AI to generate recommendations
                response = self.generation_model.generate_content(prompt)
                response_text = response.text
                
                # Find JSON array in the response
                start_idx = response_text.find('[')
                end_idx = response_text.rfind(']') + 1
                
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = response_text[start_idx:end_idx]
                    recommendations = json.loads(json_str)
                else:
                    # Fallback if JSON parsing fails
                    recommendations = [
                        {
                            "type": "investigation",
                            "description": "Investigate the security incident manually due to AI processing error.",
                            "priority": 2
                        }
                    ]
                
                return recommendations
                
            except Exception as e:
                print(f"Error generating recommendations: {e}")
                # Return a default recommendation
                return [
                    {
                        "type": "investigation",
                        "description": f"Manually investigate this security incident. Error in AI processing: {str(e)}",
                        "priority": 1
                    }
                ]
        
        # Fallback to basic recommendations if no LLM available
        return [
            {
                "type": "investigation",
                "description": "Investigate the source IP for suspicious activity.",
                "priority": 2
            },
            {
                "type": "monitoring",
                "description": "Monitor for additional similar log patterns in the next 24 hours.",
                "priority": 3
            }
        ]
    
    def update_threat_intelligence(self):
        """Update threat intelligence database from external sources"""
        # Fetch recent CVEs
        cve_data = self.threat_fetcher.fetch_cve(keywords=["remote", "execution", "critical"], max_results=20)
        
        # Fetch MITRE ATT&CK data
        mitre_data = self.threat_fetcher.fetch_mitre_attack()
        
        # Create synthetic data for demonstration
        synthetic_data = []
        
        # Add synthetic IOC data (IP addresses)
        synthetic_data.extend([
            {
                'source': 'IOC-IP',
                'reference_id': f'IP-{i}',
                'title': f'Malicious IP Address {ip}',
                'description': f'This IP address has been observed in multiple attack campaigns including phishing, malware distribution, and command and control operations.',
                'severity': 8.5,
                'published_date': datetime.datetime.now() - datetime.timedelta(days=30),
                'updated_date': datetime.datetime.now()
            } for i, ip in enumerate([
                '103.154.92.12', '185.220.101.33', '206.188.197.77', '91.109.190.8',
                '45.141.152.77', '195.123.246.138', '77.73.133.88', '185.180.197.112'
            ])
        ])
        
        # Add synthetic IOC data (domains)
        synthetic_data.extend([
            {
                'source': 'IOC-DOMAIN',
                'reference_id': f'DOMAIN-{i}',
                'title': f'Malicious Domain {domain}',
                'description': f'This domain has been associated with phishing campaigns and malware distribution. It was registered recently and shows patterns consistent with algorithmically generated domains.',
                'severity': 7.8,
                'published_date': datetime.datetime.now() - datetime.timedelta(days=15),
                'updated_date': datetime.datetime.now()
            } for i, domain in enumerate([
                'secure-banklogin.com', 'microsoft-authverify.net', 'document-preview.org',
                'account-security-check.com', 'googlemail-verify.com', 'amazonorder-tracking.net'
            ])
        ])
        
        # Add synthetic IOC data (file hashes)
        synthetic_data.extend([
            {
                'source': 'IOC-HASH',
                'reference_id': f'HASH-{i}',
                'title': f'Malicious File Hash {file_hash[:12]}...',
                'description': f'This file hash is associated with {malware_name} malware. Files with this hash have been observed executing remote code, encrypting files, and establishing persistence.',
                'severity': 9.2,
                'published_date': datetime.datetime.now() - datetime.timedelta(days=7),
                'updated_date': datetime.datetime.now()
            } for i, (file_hash, malware_name) in enumerate([
                ('a67c96bdf99ffa78331e0a7bf6c4081a1893465d', 'Emotet'),
                ('d8bbd7c5c29ab8925fa9cfd8c622ca804ac8826d', 'TrickBot'),
                ('e32856633c5e7a804eb68f5919d41a6b8cf2386c', 'Ryuk Ransomware'),
                ('f4d16c42739c1978a76a26091c8092e33d5ba8a2', 'Conti Ransomware')
            ])
        ])
        
        # Add synthetic threat actors
        synthetic_data.extend([
            {
                'source': 'MITRE-GROUP',
                'reference_id': f'G{i}',
                'title': name,
                'description': description,
                'severity': severity,
                'published_date': datetime.datetime.now() - datetime.timedelta(days=180),
                'updated_date': datetime.datetime.now() - datetime.timedelta(days=i)
            } for i, (name, description, severity) in enumerate([
                ('APT29', 'Sophisticated threat actor associated with Russian intelligence services. Known for targeted operations against government, diplomatic, and research entities.', 9.0),
                ('Lazarus Group', 'Threat actor associated with North Korea. Known for financially motivated attacks, cryptocurrency theft, and espionage operations.', 8.7),
                ('Kimsuky', 'Threat actor focused on intelligence gathering on foreign policy and national security issues. Primarily targets government entities.', 7.5),
                ('Mustang Panda', 'Threat actor that targets organizations across multiple sectors with a focus on intelligence gathering. Known for using themed lures.', 7.8)
            ])
        ])
        
        # Combine all threat data
        all_threats = cve_data + mitre_data + synthetic_data
        
        # Generate embeddings for all threat descriptions
        descriptions = [
            f"{threat['title']} {threat['description']}" for threat in all_threats
        ]
        embeddings = self.embeddings.get_batch_embeddings(descriptions)
        
        # Save to database
        for i, threat in enumerate(all_threats):
            # Check if threat already exists
            existing = self.db.query(ThreatIntelligence).filter_by(
                source=threat['source'],
                reference_id=threat['reference_id']
            ).first()
            
            if existing:
                # Update existing threat
                existing.title = threat['title']
                existing.description = threat['description']
                existing.severity = threat['severity']
                existing.updated_date = threat['updated_date']
                existing.embedding = embeddings[i]
            else:
                # Add new threat
                new_threat = ThreatIntelligence(
                    source=threat['source'],
                    reference_id=threat['reference_id'],
                    title=threat['title'],
                    description=threat['description'],
                    severity=threat['severity'],
                    published_date=threat['published_date'],
                    updated_date=threat['updated_date'],
                    embedding=embeddings[i]
                )
                self.db.add(new_threat)
        
        # Commit changes
        self.db.commit()
        
        return {
            "updated": len(all_threats),
            "sources": list(set(t['source'] for t in all_threats))
        }
    
    def _extract_iocs(self, parsed_log: Dict) -> List[Dict]:
        """Extract potential indicators of compromise from parsed log
        
        Args:
            parsed_log: The parsed log data
            
        Returns:
            List of potential IOCs with type and value
        """
        iocs = []
        
        # Extract IP addresses
        for field in ["source_ip", "destination_ip", "ip_address", "remote_address"]:
            if field in parsed_log and parsed_log[field]:
                ip = parsed_log[field]
                
                # Verify this is a valid IP and not a private/internal one
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                        iocs.append({
                            "type": "ip",
                            "value": ip,
                            "source_field": field,
                            "reputation": "Unknown"  # Will be enriched later
                        })
                except ValueError:
                    # Not a valid IP address
                    pass
        
        # Extract domains/hostnames
        for field in ["hostname", "domain", "target", "url", "host"]:
            if field in parsed_log and parsed_log[field]:
                value = parsed_log[field]
                
                # Simple validation to avoid internal hostnames
                if "." in value and not value.startswith("127.0.0.1") and not value.startswith("localhost"):
                    iocs.append({
                        "type": "domain",
                        "value": value,
                        "source_field": field,
                        "reputation": "Unknown"
                    })
        
        # Extract file hashes if present
        for field in ["md5", "sha1", "sha256", "hash", "file_hash"]:
            if field in parsed_log and parsed_log[field]:
                iocs.append({
                    "type": "hash",
                    "value": parsed_log[field],
                    "hash_type": field.split("_")[-1],
                    "source_field": field,
                    "reputation": "Unknown"
                })
        
        return iocs
    
    def _find_related_iocs(self, extracted_iocs: List[Dict]) -> Dict:
        """Find related IOCs in threat intelligence database
        
        Args:
            extracted_iocs: List of extracted IOCs from log
            
        Returns:
            Dictionary of related threat intelligence
        """
        related = {
            "matches": [],
            "possible_matches": []
        }
        
        for ioc in extracted_iocs:
            # Look for exact matches in threat intelligence
            if ioc["type"] == "ip":
                # Look for this IP in our IOC-IP entries
                threat = self.db.query(ThreatIntelligence).filter(
                    ThreatIntelligence.source == "IOC-IP",
                    ThreatIntelligence.title.like(f"%{ioc['value']}%")
                ).first()
                
                if threat:
                    related["matches"].append({
                        "ioc": ioc,
                        "threat": {
                            "id": threat.id,
                            "title": threat.title,
                            "description": threat.description,
                            "severity": threat.severity,
                            "source": threat.source
                        },
                        "confidence": 100  # Exact match
                    })
            
            elif ioc["type"] == "domain":
                # Look for this domain in our IOC-DOMAIN entries
                threat = self.db.query(ThreatIntelligence).filter(
                    ThreatIntelligence.source == "IOC-DOMAIN",
                    ThreatIntelligence.title.like(f"%{ioc['value']}%")
                ).first()
                
                if threat:
                    related["matches"].append({
                        "ioc": ioc,
                        "threat": {
                            "id": threat.id,
                            "title": threat.title,
                            "description": threat.description,
                            "severity": threat.severity,
                            "source": threat.source
                        },
                        "confidence": 100  # Exact match
                    })
            
            elif ioc["type"] == "hash":
                # Look for this hash in our IOC-HASH entries
                threat = self.db.query(ThreatIntelligence).filter(
                    ThreatIntelligence.source == "IOC-HASH",
                    ThreatIntelligence.title.like(f"%{ioc['value'][:12]}%")
                ).first()
                
                if threat:
                    related["matches"].append({
                        "ioc": ioc,
                        "threat": {
                            "id": threat.id,
                            "title": threat.title,
                            "description": threat.description,
                            "severity": threat.severity,
                            "source": threat.source
                        },
                        "confidence": 100  # Exact match
                    })
        
        # If we have no exact matches, try semantic search
        if not related["matches"] and extracted_iocs:
            # Create a query from the IOCs
            query = " ".join([f"{ioc['type']} {ioc['value']}" for ioc in extracted_iocs])
            
            # Get embedding for the query
            query_embedding = self.embeddings.get_embedding(query)
            
            # Find similar threats
            sql = text("""
                SELECT id, 1 - (embedding <=> :query_embedding) as similarity
                FROM threat_intelligence
                WHERE similarity > 0.7
                ORDER BY similarity DESC
                LIMIT 5
            """)
            
            result = self.db.execute(sql, {
                "query_embedding": query_embedding
            })
            
            # Get threat IDs and similarities
            threat_matches = [(row[0], row[1]) for row in result]
            
            # Fetch full threat objects
            for threat_id, similarity in threat_matches:
                threat = self.db.query(ThreatIntelligence).filter_by(id=threat_id).first()
                if threat:
                    related["possible_matches"].append({
                        "threat": {
                            "id": threat.id,
                            "title": threat.title,
                            "description": threat.description,
                            "severity": threat.severity,
                            "source": threat.source
                        },
                        "confidence": round(similarity * 100, 1)
                    })
        
        return related
    
    def _generate_incident_description(self, parsed_log: Dict) -> str:
        # Implement the logic to generate a description based on the parsed log
        # This is a placeholder and should be replaced with the actual implementation
        return f"Potential security incident from {parsed_log.get('source_ip', 'unknown')}"
