#!/usr/bin/env python3
"""
Chronicle SIEM Orchestration Platform
Intelligent automation and ML-based triage for Chronicle SIEM
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import sqlite3
import requests
import yaml
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AlertStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

@dataclass
class ChronicleAlert:
    alert_id: str
    rule_name: str
    severity: AlertSeverity
    timestamp: datetime
    source_ip: str
    destination_ip: str
    user: str
    event_type: str
    raw_log: str
    status: AlertStatus = AlertStatus.NEW
    confidence_score: float = 0.0
    ml_features: Dict = None
    threat_intel: Dict = None
    response_actions: List[str] = None

class MLTriageEngine:
    """Machine Learning engine for intelligent alert triage"""
    
    def __init__(self, model_path: str = "models/triage_model.pkl"):
        self.model_path = model_path
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'source_ip_reputation',
            'destination_port', 'event_frequency', 'user_risk_score',
            'geo_distance', 'time_since_last_login'
        ]
        
    def extract_features(self, alert: ChronicleAlert) -> Dict:
        """Extract ML features from Chronicle alert"""
        features = {}
        
        # Temporal features
        features['hour_of_day'] = alert.timestamp.hour
        features['day_of_week'] = alert.timestamp.weekday()
        
        # Network features
        features['source_ip_reputation'] = self.get_ip_reputation_score(alert.source_ip)
        features['destination_port'] = self.extract_port_from_log(alert.raw_log)
        
        # Behavioral features
        features['event_frequency'] = self.calculate_event_frequency(alert)
        features['user_risk_score'] = self.calculate_user_risk_score(alert.user)
        
        # Geographical features
        features['geo_distance'] = self.calculate_geo_distance(alert.source_ip, alert.user)
        
        # Historical features
        features['time_since_last_login'] = self.get_time_since_last_login(alert.user)
        
        return features
    
    def get_ip_reputation_score(self, ip: str) -> float:
        """Get IP reputation score (0-1, higher = more suspicious)"""
        # This would integrate with threat intelligence feeds
        # For demo, we'll simulate based on IP characteristics
        
        if ip.startswith('10.') or ip.startswith('192.168.'):
            return 0.1  # Internal IP, low suspicion
        elif ip.startswith('172.'):
            return 0.2  # Private range
        else:
            # External IP - check against known bad IPs
            # For demo, simulate higher risk for certain IPs
            if '185.220.100' in ip or '203.0.113' in ip:
                return 0.8  # Known suspicious ranges
            hash_val = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            return min((hash_val % 100) / 100.0, 0.6)
    
    def extract_port_from_log(self, raw_log: str) -> int:
        """Extract destination port from raw log"""
        import re
        port_match = re.search(r'(?:dst_port[=:]|port\s+)(\d+)', raw_log)
        if port_match:
            return int(port_match.group(1))
        # Default ports based on common services
        if 'ssh' in raw_log.lower():
            return 22
        elif 'https' in raw_log.lower():
            return 443
        elif 'http' in raw_log.lower():
            return 80
        return 80
    
    def calculate_event_frequency(self, alert: ChronicleAlert) -> float:
        """Calculate how frequently this type of event occurs"""
        # This would query Chronicle for similar events
        # For demo, simulate based on event type
        frequency_map = {
            'authentication_failure': 0.8,
            'privilege_escalation': 0.1,
            'data_exfiltration': 0.05,
            'malware_detection': 0.02,
            'lateral_movement': 0.07
        }
        return frequency_map.get(alert.event_type, 0.5)
    
    def calculate_user_risk_score(self, user: str) -> float:
        """Calculate user risk score based on historical behavior"""
        # This would integrate with user behavior analytics
        # For demo, simulate based on user characteristics
        if 'admin' in user.lower() or 'root' in user.lower():
            return 0.7  # Admins are higher risk
        elif 'service' in user.lower() or '@' not in user:
            return 0.3  # Service accounts medium risk
        elif 'trading' in user.lower() or 'financial' in user.lower():
            return 0.6  # Financial users higher risk
        else:
            return 0.4  # Regular users baseline
    
    def calculate_geo_distance(self, ip: str, user: str) -> float:
        """Calculate geographical distance anomaly"""
        # This would use GeoIP databases
        # For demo, simulate based on IP/user combination
        if ip.startswith('185.220'):  # TOR exit nodes
            return 0.9  # High geographic anomaly
        elif ip.startswith('10.') or ip.startswith('192.168.'):
            return 0.1  # Internal network, low anomaly
        return np.random.uniform(0.2, 0.7)
    
    def get_time_since_last_login(self, user: str) -> float:
        """Get hours since last login for user"""
        # This would query user activity database
        # For demo, simulate realistic values
        if 'admin' in user.lower():
            return np.random.exponential(8)  # Admins login more frequently
        return np.random.exponential(24)  # Average 24 hours
    
    def train_model(self, training_alerts: List[ChronicleAlert], labels: List[bool]):
        """Train the ML models on historical data"""
        logger.info("Training ML triage models...")
        
        # Extract features for all training alerts
        features_list = []
        for alert in training_alerts:
            features = self.extract_features(alert)
            # Ensure all features are present
            feature_vector = [features.get(col, 0) for col in self.feature_columns]
            features_list.append(feature_vector)
        
        X = np.array(features_list)
        y = np.array(labels)  # True = legitimate alert, False = false positive
        
        if len(X) == 0:
            logger.warning("No training data available, using default model")
            self.is_trained = False
            return
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train anomaly detection model
        self.isolation_forest.fit(X_train_scaled)
        
        # Train classification model
        self.classifier.fit(X_train_scaled, y_train)
        
        # Evaluate models
        if len(X_test) > 0:
            anomaly_predictions = self.isolation_forest.predict(X_test_scaled)
            class_predictions = self.classifier.predict(X_test_scaled)
            
            accuracy = np.mean(class_predictions == y_test) if len(y_test) > 0 else 0.5
            logger.info(f"Model training complete. Accuracy: {accuracy:.3f}")
        
        # Save models
        self.save_models()
        self.is_trained = True
    
    def predict_alert_legitimacy(self, alert: ChronicleAlert) -> Tuple[bool, float]:
        """Predict if alert is legitimate and return confidence score"""
        if not self.is_trained:
            # If not trained, use heuristic-based scoring
            return self._heuristic_scoring(alert)
        
        features = self.extract_features(alert)
        feature_vector = np.array([[features.get(col, 0) for col in self.feature_columns]])
        feature_vector_scaled = self.scaler.transform(feature_vector)
        
        # Get anomaly score
        anomaly_score = self.isolation_forest.decision_function(feature_vector_scaled)[0]
        
        # Get classification probability
        class_proba = self.classifier.predict_proba(feature_vector_scaled)[0]
        legitimate_proba = class_proba[1] if len(class_proba) > 1 else 0.5
        
        # Combine scores
        combined_confidence = (legitimate_proba + (anomaly_score + 0.5)) / 2
        is_legitimate = combined_confidence > 0.6
        
        return is_legitimate, combined_confidence
    
    def _heuristic_scoring(self, alert: ChronicleAlert) -> Tuple[bool, float]:
        """Fallback heuristic scoring when ML models aren't trained"""
        features = self.extract_features(alert)
        
        # Simple rule-based scoring
        score = 0.5  # Base score
        
        # High risk indicators
        if features['source_ip_reputation'] > 0.7:
            score += 0.3
        if features['hour_of_day'] < 6 or features['hour_of_day'] > 22:
            score += 0.1  # After hours
        if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            score += 0.2
        if features['user_risk_score'] > 0.6:
            score += 0.1
        if features['geo_distance'] > 0.8:
            score += 0.2
        
        # Low risk indicators
        if features['source_ip_reputation'] < 0.2:
            score -= 0.1
        if features['event_frequency'] > 0.5:
            score -= 0.1  # Common events less likely to be threats
        
        confidence = min(max(score, 0.1), 0.95)
        is_legitimate = confidence > 0.6
        
        return is_legitimate, confidence
    
    def save_models(self):
        """Save trained models to disk"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        models = {
            'isolation_forest': self.isolation_forest,
            'classifier': self.classifier,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns
        }
        
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(models, f)
            logger.info(f"Models saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                models = pickle.load(f)
            
            self.isolation_forest = models['isolation_forest']
            self.classifier = models['classifier']
            self.scaler = models['scaler']
            self.feature_columns = models['feature_columns']
            self.is_trained = True
            
            logger.info(f"Models loaded from {self.model_path}")
        except FileNotFoundError:
            logger.warning(f"No saved models found at {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")

class ThreatIntelligenceEnricher:
    """Enriches alerts with threat intelligence data"""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
        
    async def enrich_alert(self, alert: ChronicleAlert) -> Dict:
        """Enrich alert with threat intelligence"""
        enrichment = {
            'ip_reputation': await self.get_ip_intelligence(alert.source_ip),
            'domain_reputation': await self.get_domain_intelligence(alert.raw_log),
            'hash_reputation': await self.get_hash_intelligence(alert.raw_log),
            'user_context': await self.get_user_context(alert.user),
            'attack_patterns': await self.get_attack_patterns(alert)
        }
        
        return enrichment
    
    async def get_ip_intelligence(self, ip: str) -> Dict:
        """Get threat intelligence for IP address"""
        cache_key = f"ip_{ip}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # This would integrate with real threat intel APIs
        # For demo, simulate intelligence data
        intel = {
            'reputation': 'clean',
            'categories': [],
            'first_seen': datetime.now() - timedelta(days=30),
            'last_seen': datetime.now(),
            'malware_families': [],
            'threat_actors': [],
            'geolocation': 'US'
        }
        
        # Simulate threat intelligence for specific IPs
        if '185.220.100' in ip:  # TOR exit nodes
            intel.update({
                'reputation': 'suspicious',
                'categories': ['anonymizer', 'tor_exit'],
                'threat_actors': ['Various'],
                'geolocation': 'Multiple'
            })
        elif '203.0.113' in ip:  # RFC 5737 test range, simulate malicious
            intel.update({
                'reputation': 'malicious',
                'categories': ['malware', 'c2'],
                'malware_families': ['Emotet', 'TrickBot'],
                'threat_actors': ['APT29', 'FIN7']
            })
        elif ip.startswith('10.') or ip.startswith('192.168.'):
            intel.update({
                'reputation': 'internal',
                'categories': ['private_network'],
                'geolocation': 'Internal'
            })
        
        self.cache[cache_key] = intel
        return intel
    
    async def get_domain_intelligence(self, raw_log: str) -> Dict:
        """Extract and analyze domains from log"""
        import re
        domains = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_log)
        
        domain_intel = {}
        for domain in domains[:5]:  # Limit to first 5 domains
            if domain.endswith('.local') or domain.endswith('.internal'):
                reputation = 'internal'
            elif any(suspicious in domain for suspicious in ['temp', 'bit.ly', 'tinyurl']):
                reputation = 'suspicious'
            else:
                reputation = 'clean'
                
            domain_intel[domain] = {
                'reputation': reputation,
                'categories': ['url_shortener'] if 'bit.ly' in domain or 'tinyurl' in domain else [],
                'creation_date': None,
                'registrar': None
            }
        
        return domain_intel
    
    async def get_hash_intelligence(self, raw_log: str) -> Dict:
        """Extract and analyze file hashes from log"""
        import re
        # Look for MD5, SHA1, SHA256 hashes
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', raw_log)
        
        hash_intel = {}
        for hash_val in hashes[:3]:  # Limit to first 3 hashes
            # Simulate hash reputation
            if len(hash_val) == 32:  # MD5
                hash_type = 'md5'
            elif len(hash_val) == 40:  # SHA1
                hash_type = 'sha1'
            elif len(hash_val) == 64:  # SHA256
                hash_type = 'sha256'
            else:
                hash_type = 'unknown'
                
            hash_intel[hash_val] = {
                'hash_type': hash_type,
                'reputation': 'unknown',
                'malware_family': None,
                'first_seen': None,
                'submission_count': 0
            }
        
        return hash_intel
    
    async def get_user_context(self, user: str) -> Dict:
        """Get contextual information about user"""
        # Simulate user context based on user patterns
        if 'admin' in user.lower():
            department = 'IT Security'
            risk_score = 0.7
        elif 'trading' in user.lower():
            department = 'Trading'
            risk_score = 0.6
        elif 'financial' in user.lower() or 'finance' in user.lower():
            department = 'Finance'
            risk_score = 0.5
        else:
            department = 'General'
            risk_score = 0.3
            
        return {
            'department': department,
            'risk_score': risk_score,
            'recent_activities': [],
            'access_patterns': {
                'normal_hours': [9, 17],
                'typical_locations': ['US', 'UK'],
                'common_systems': ['workstation', 'email', 'trading_platform']
            },
            'clearance_level': 'confidential' if 'admin' in user.lower() or 'trading' in user.lower() else 'public'
        }
    
    async def get_attack_patterns(self, alert: ChronicleAlert) -> Dict:
        """Identify attack patterns and tactics"""
        patterns = {
            'mitre_tactics': [],
            'attack_techniques': [],
            'campaign_indicators': []
        }
        
        # Map event types to MITRE ATT&CK
        if alert.event_type == 'authentication_failure':
            patterns['mitre_tactics'] = ['Credential Access']
            patterns['attack_techniques'] = ['T1110 - Brute Force']
        elif alert.event_type == 'privilege_escalation':
            patterns['mitre_tactics'] = ['Privilege Escalation']
            patterns['attack_techniques'] = ['T1068 - Exploitation for Privilege Escalation']
        elif alert.event_type == 'data_exfiltration':
            patterns['mitre_tactics'] = ['Exfiltration']
            patterns['attack_techniques'] = ['T1041 - Exfiltration Over C2 Channel']
        elif alert.event_type == 'lateral_movement':
            patterns['mitre_tactics'] = ['Lateral Movement']
            patterns['attack_techniques'] = ['T1021 - Remote Services']
        
        # Check for campaign indicators
        if '185.220.100' in alert.source_ip:
            patterns['campaign_indicators'] = ['TOR-based campaign']
        if 'trading' in alert.user.lower():
            patterns['campaign_indicators'].append('Financial sector targeting')
        
        return patterns

class AutomatedResponseEngine:
    """Handles automated response actions for alerts"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.response_actions = {
            'isolate_host': self.isolate_host,
            'disable_user': self.disable_user,
            'block_ip': self.block_ip,
            'collect_artifacts': self.collect_artifacts,
            'notify_team': self.notify_team,
            'quarantine_file': self.quarantine_file,
            'reset_password': self.reset_password
        }
        
    async def execute_response(self, alert: ChronicleAlert, actions: List[str]) -> Dict:
        """Execute automated response actions"""
        results = {}
        
        for action in actions:
            if action in self.response_actions:
                try:
                    result = await self.response_actions[action](alert)
                    results[action] = {'status': 'success', 'result': result}
                    logger.info(f"Executed {action} for alert {alert.alert_id}")
                except Exception as e:
                    results[action] = {'status': 'error', 'error': str(e)}
                    logger.error(f"Failed to execute {action}: {e}")
            else:
                results[action] = {'status': 'error', 'error': 'Unknown action'}
        
        return results
    
    async def isolate_host(self, alert: ChronicleAlert) -> str:
        """Isolate compromised host"""
        # This would integrate with endpoint protection platforms
        # For demo, simulate the action
        logger.info(f"Isolating host with IP {alert.source_ip}")
        
        # Simulate API call to endpoint protection
        isolation_id = f"iso_{alert.alert_id[:8]}"
        
        return f"Host {alert.source_ip} isolated successfully. Isolation ID: {isolation_id}"
    
    async def disable_user(self, alert: ChronicleAlert) -> str:
        """Disable user account"""
        # This would integrate with Identity Management systems
        logger.info(f"Disabling user account: {alert.user}")
        
        # Simulate API call to identity provider
        disable_id = f"disable_{alert.alert_id[:8]}"
        
        return f"User account {alert.user} disabled. Disable ID: {disable_id}"
    
    async def block_ip(self, alert: ChronicleAlert) -> str:
        """Block malicious IP address"""
        # This would integrate with firewall/security appliances
        logger.info(f"Blocking IP address: {alert.source_ip}")
        
        # Simulate firewall rule creation
        rule_id = f"rule_{alert.alert_id[:8]}"
        
        return f"IP {alert.source_ip} blocked successfully. Rule ID: {rule_id}"
    
    async def collect_artifacts(self, alert: ChronicleAlert) -> str:
        """Collect forensic artifacts"""
        logger.info(f"Collecting artifacts for alert {alert.alert_id}")
        
        artifacts = {
            'network_flows': f"flows_{alert.alert_id}.pcap",
            'system_logs': f"logs_{alert.alert_id}.zip",
            'memory_dump': f"memory_{alert.alert_id}.raw" if alert.severity == AlertSeverity.CRITICAL else None,
            'disk_image': f"disk_{alert.alert_id}.img" if alert.severity == AlertSeverity.CRITICAL else None
        }
        
        # Filter out None values
        artifacts = {k: v for k, v in artifacts.items() if v is not None}
        
        return f"Artifacts collected: {', '.join(artifacts.values())}"
    
    async def notify_team(self, alert: ChronicleAlert) -> str:
        """Notify security team"""
        logger.info(f"Notifying security team about alert {alert.alert_id}")
        
        # This would integrate with communication platforms (Slack, Teams, etc.)
        notification = {
            'channel': '#security-alerts',
            'message': f"🚨 {alert.severity.name} priority alert: {alert.rule_name}",
            'alert_id': alert.alert_id,
            'user': alert.user,
            'source_ip': alert.source_ip
        }
        
        return f"Team notified via {notification['channel']} - Alert: {alert.alert_id}"
    
    async def quarantine_file(self, alert: ChronicleAlert) -> str:
        """Quarantine malicious file"""
        logger.info(f"Quarantining file from alert {alert.alert_id}")
        
        quarantine_id = f"quar_{alert.alert_id[:8]}"
        return f"File quarantined successfully. Quarantine ID: {quarantine_id}"
    
    async def reset_password(self, alert: ChronicleAlert) -> str:
        """Reset user password"""
        logger.info(f"Resetting password for user: {alert.user}")
        
        reset_id = f"reset_{alert.alert_id[:8]}"
        return f"Password reset initiated for {alert.user}. Reset ID: {reset_id}"

class ChronicleOrchestrator:
    """Main orchestration engine for Chronicle SIEM automation"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ml_engine = MLTriageEngine()
        self.threat_intel = ThreatIntelligenceEnricher()
        self.response_engine = AutomatedResponseEngine(config)
        self.db_path = config.get('database_path', 'data/chronicle_orchestration.db')
        self.init_database()
        
        # Load existing models if available
        self.ml_engine.load_models()
        
    def init_database(self):
        """Initialize database for storing alerts and analysis"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_name TEXT,
                severity TEXT,
                timestamp TIMESTAMP,
                source_ip TEXT,
                destination_ip TEXT,
                user_name TEXT,
                event_type TEXT,
                status TEXT,
                confidence_score REAL,
                ml_features TEXT,
                threat_intel TEXT,
                response_actions TEXT,
                raw_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_data (
                alert_id TEXT PRIMARY KEY,
                features TEXT,
                label INTEGER,
                analyst_feedback TEXT,
                created_date TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def process_chronicle_alert(self, alert_data: Dict) -> ChronicleAlert:
        """Process incoming alert from Chronicle SIEM"""
        logger.info(f"Processing Chronicle alert: {alert_data.get('id', 'unknown')}")
        
        # Parse timestamp
        timestamp_str = alert_data.get('timestamp', datetime.now().isoformat())
        if isinstance(timestamp_str, str):
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        else:
            timestamp = timestamp_str
        
        # Create alert object
        alert = ChronicleAlert(
            alert_id=alert_data.get('id', f"alert_{datetime.now().timestamp()}"),
            rule_name=alert_data.get('rule_name', 'Unknown Rule'),
            severity=AlertSeverity(alert_data.get('severity', 2)),
            timestamp=timestamp,
            source_ip=alert_data.get('source_ip', '0.0.0.0'),
            destination_ip=alert_data.get('destination_ip', '0.0.0.0'),
            user=alert_data.get('user', 'unknown'),
            event_type=alert_data.get('event_type', 'unknown'),
            raw_log=alert_data.get('raw_log', ''),
            response_actions=[]
        )
        
        # Step 1: ML-based triage
        is_legitimate, confidence = self.ml_engine.predict_alert_legitimacy(alert)
        alert.confidence_score = confidence
        
        # Step 2: Threat intelligence enrichment
        threat_intel = await self.threat_intel.enrich_alert(alert)
        alert.threat_intel = threat_intel
        
        # Step 3: Determine response actions
        response_actions = self.determine_response_actions(alert, is_legitimate, threat_intel)
        alert.response_actions = response_actions
        
        # Step 4: Execute automated responses if needed
        if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL] and is_legitimate and confidence > 0.8:
            response_results = await self.response_engine.execute_response(alert, response_actions)
            logger.info(f"Automated responses executed: {response_results}")
        
        # Step 5: Store alert
        self.store_alert(alert)
        
        return alert
    
    def determine_response_actions(self, alert: ChronicleAlert, is_legitimate: bool, 
                                 threat_intel: Dict) -> List[str]:
        """Determine appropriate response actions based on alert analysis"""
        actions = ['collect_artifacts', 'notify_team']  # Always do these
        
        if not is_legitimate or alert.confidence_score < 0.5:
            alert.status = AlertStatus.FALSE_POSITIVE
            return ['notify_team']  # Minimal response for false positives
        
        # Check threat intelligence
        ip_intel = threat_intel.get('ip_reputation', {})
        if ip_intel.get('reputation') in ['malicious', 'suspicious']:
            actions.append('block_ip')
        
        # User context considerations
        user_context = threat_intel.get('user_context', {})
        if user_context.get('risk_score', 0) > 0.6:
            actions.append('reset_password')
        
        # Severity-based actions
        if alert.severity == AlertSeverity.CRITICAL:
            actions.extend(['isolate_host', 'disable_user'])
            if alert.confidence_score > 0.9:
                actions.append('quarantine_file')
        elif alert.severity == AlertSeverity.HIGH:
            if alert.confidence_score > 0.8:
                actions.append('isolate_host')
            if 'trading' in alert.user.lower() or 'admin' in alert.user.lower():
                actions.append('disable_user')
        
        # Event-type specific actions
        if alert.event_type in ['privilege_escalation', 'lateral_movement']:
            actions.append('disable_user')
        elif alert.event_type == 'data_exfiltration':
            actions.extend(['isolate_host', 'block_ip'])
        
        return list(set(actions))  # Remove duplicates
    
    def store_alert(self, alert: ChronicleAlert):
        """Store alert in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO alerts 
            (alert_id, rule_name, severity, timestamp, source_ip, destination_ip, 
             user_name, event_type, status, confidence_score, ml_features, 
             threat_intel, response_actions, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id,
            alert.rule_name,
            alert.severity.name,
            alert.timestamp,
            alert.source_ip,
            alert.destination_ip,
            alert.user,
            alert.event_type,
            alert.status.value,
            alert.confidence_score,
            json.dumps(alert.ml_features) if alert.ml_features else None,
            json.dumps(alert.threat_intel, default=str) if alert.threat_intel else None,
            json.dumps(alert.response_actions) if alert.response_actions else None,
            json.dumps(asdict(alert), default=str)
        ))
        
        conn.commit()
        conn.close()
    
    def get_analytics_dashboard_data(self) -> Dict:
        """Generate data for analytics dashboard"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Query recent alerts
            df = pd.read_sql_query('''
                SELECT * FROM alerts 
                WHERE timestamp > datetime('now', '-7 days')
                ORDER BY timestamp DESC
            ''', conn)
            
            conn.close()
            
            if df.empty:
                return {
                    'message': 'Demo analytics data',
                    'total_alerts': 156,
                    'alerts_by_severity': {'HIGH': 45, 'MEDIUM': 67, 'LOW': 44},
                    'alerts_by_status': {'triaged': 89, 'resolved': 52, 'false_positive': 15},
                    'average_confidence': 0.847,
                    'false_positive_rate': 12.8,
                    'top_sources': {'185.220.100.240': 8, '203.0.113.50': 5},
                    'top_users': {'admin@swift.com': 12, 'trading@swift.com': 8}
                }
            
            analytics = {
                'total_alerts': len(df),
                'alerts_by_severity': df['severity'].value_counts().to_dict(),
                'alerts_by_status': df['status'].value_counts().to_dict(),
                'average_confidence': df['confidence_score'].mean(),
                'false_positive_rate': (df['status'] == 'false_positive').mean() * 100,
                'top_sources': df['source_ip'].value_counts().head(10).to_dict(),
                'top_users': df['user_name'].value_counts().head(10).to_dict(),
                'recent_high_confidence': df[df['confidence_score'] > 0.8].head(5)[
                    ['alert_id', 'rule_name', 'severity', 'confidence_score']
                ].to_dict('records')
            }
            
            return analytics
        except Exception as e:
            logger.error(f"Error generating analytics: {e}")
            return {'error': 'Failed to generate analytics', 'message': str(e)}

# Example usage and testing
def main():
    """Example usage of Chronicle Orchestration Platform"""
    
    config = {
        'database_path': 'data/chronicle_orchestration.db',
        'chronicle_project': 'demo-project',
        'response_config': {
            'auto_isolate_threshold': 0.8,
            'auto_block_threshold': 0.9
        }
    }
    
    orchestrator = ChronicleOrchestrator(config)
    
    # Simulate some Chronicle alerts
    sample_alerts = [
        {
            'id': 'CHR_001_20240115_103000',
            'rule_name': 'Suspicious Login from TOR Exit Node',
            'severity': 3,
            'timestamp': datetime.now().isoformat(),
            'source_ip': '185.220.100.240',
            'destination_ip': '10.0.1.50',
            'user': 'trading_admin@swift.com',
            'event_type': 'authentication_failure',
            'raw_log': 'Failed login attempt for user trading_admin@swift.com from TOR exit node 185.220.100.240'
        },
        {
            'id': 'CHR_002_20240115_111500',
            'rule_name': 'Privilege Escalation via Service Account',
            'severity': 4,
            'timestamp': datetime.now().isoformat(),
            'source_ip': '10.0.1.100',
            'destination_ip': '10.0.1.10',
            'user': 'payment_processor@swift.com',
            'event_type': 'privilege_escalation',
            'raw_log': 'Service account payment_processor@swift.com gained administrative privileges outside normal workflow'
        },
        {
            'id': 'CHR_003_20240115_120000',
            'rule_name': 'Unusual Wire Transfer Data Access',
            'severity': 4,
            'timestamp': datetime.now().isoformat(),
            'source_ip': '10.0.2.25',
            'destination_ip': '203.0.113.50',
            'user': 'back_office@swift.com',
            'event_type': 'data_exfiltration',
            'raw_log': 'Large data export from wire transfer database: 10GB to external IP 203.0.113.50'
        }
    ]
    
    async def process_alerts():
        processed_alerts = []
        
        for alert_data in sample_alerts:
            alert = await orchestrator.process_chronicle_alert(alert_data)
            processed_alerts.append(alert)
            
            print(f"\n🔍 ALERT PROCESSED: {alert.alert_id}")
            print(f"Rule: {alert.rule_name}")
            print(f"Confidence: {alert.confidence_score:.2f}")
            print(f"Status: {alert.status.value}")
            print(f"Actions: {', '.join(alert.response_actions)}")
        
        # Generate analytics
        analytics = orchestrator.get_analytics_dashboard_data()
        print(f"\n📊 ANALYTICS SUMMARY:")
        print(f"Total Alerts: {analytics.get('total_alerts', 0)}")
        print(f"False Positive Rate: {analytics.get('false_positive_rate', 0):.1f}%")
        print(f"Average Confidence: {analytics.get('average_confidence', 0):.2f}")
        
        return processed_alerts
    
    # Run the alert processing
    alerts = asyncio.run(process_alerts())
    print(f"\n✅ Processed {len(alerts)} alerts successfully")

if __name__ == "__main__":
    main()
