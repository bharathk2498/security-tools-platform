#!/usr/bin/env python3
"""
AI-Powered Attack Surface Discovery Engine
Core module for intelligent asset discovery and risk assessment
"""

import asyncio
import json
import requests
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import hashlib
import sqlite3
from dataclasses import dataclass
from google.cloud import asset_v1
from google.cloud import securitycenter
import shodan
import censys.search
from concurrent.futures import ThreadPoolExecutor

@dataclass
class AssetRisk:
    asset_id: str
    asset_type: str
    exposure_level: int  # 1-5 scale
    threat_context: Dict
    vulnerabilities: List[str]
    risk_score: float
    last_updated: datetime

class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple sources"""
    
    def __init__(self):
        self.sources = {
            'otx': 'https://otx.alienvault.com/api/v1/',
            'vt': 'https://www.virustotal.com/vtapi/v2/',
            'misp': None,  # Configure based on your MISP instance
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        }
        self.cache = {}
        
    def get_cve_context(self, cve_id: str) -> Dict:
        """Get threat context for a specific CVE"""
        if cve_id in self.cache:
            return self.cache[cve_id]
            
        context = {
            'exploited_in_wild': False,
            'exploit_availability': 'unknown',
            'threat_actors': [],
            'campaigns': []
        }
        
        # Check CISA KEV
        try:
            response = requests.get(self.sources['cisa_kev'], timeout=10)
            kev_data = response.json()
            
            for vuln in kev_data.get('vulnerabilities', []):
                if vuln.get('cveID') == cve_id:
                    context['exploited_in_wild'] = True
                    context['exploit_availability'] = 'confirmed'
                    break
        except Exception as e:
            print(f"Error checking CISA KEV: {e}")
            
        self.cache[cve_id] = context
        return context
    
    def get_ip_reputation(self, ip_address: str) -> Dict:
        """Get threat intelligence for IP address"""
        reputation = {
            'malicious': False,
            'categories': [],
            'last_seen': None,
            'confidence': 0
        }
        
        # Add your threat intel API calls here
        # Example: VirusTotal, Shodan, etc.
        
        return reputation

class CloudAssetDiscovery:
    """Discovers assets across cloud platforms"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.asset_client = asset_v1.AssetServiceClient() if project_id != 'demo-project' else None
        
    async def discover_gcp_assets(self) -> List[Dict]:
        """Discover all GCP assets"""
        assets = []
        
        # For demo mode, return sample data
        if self.project_id == 'demo-project' or not self.asset_client:
            return self._get_demo_assets()
        
        try:
            # Search all resources in the project
            scope = f"projects/{self.project_id}"
            
            request = asset_v1.SearchAllResourcesRequest(
                scope=scope,
                asset_types=[
                    "compute.googleapis.com/Instance",
                    "compute.googleapis.com/Address",
                    "storage.googleapis.com/Bucket",
                    "dns.googleapis.com/ManagedZone",
                    "compute.googleapis.com/ForwardingRule"
                ]
            )
            
            response = self.asset_client.search_all_resources(request=request)
            
            for resource in response:
                asset = {
                    'id': resource.name,
                    'type': resource.asset_type,
                    'location': resource.location,
                    'labels': dict(resource.labels) if resource.labels else {},
                    'network_tags': getattr(resource, 'network_tags', []),
                    'state': resource.state if hasattr(resource, 'state') else 'UNKNOWN',
                    'creation_time': resource.create_time.timestamp() if resource.create_time else None
                }
                assets.append(asset)
                
        except Exception as e:
            print(f"Error discovering GCP assets: {e}")
            return self._get_demo_assets()
            
        return assets
    
    def _get_demo_assets(self) -> List[Dict]:
        """Return demo assets for demonstration"""
        return [
            {
                'id': 'projects/swift-demo/instances/web-server-prod-1',
                'type': 'compute.googleapis.com/Instance',
                'location': 'us-central1-a',
                'labels': {'environment': 'production', 'tier': 'web', 'criticality': 'high'},
                'network_tags': ['web-server', 'https-server'],
                'external_ip': '203.0.113.10',
                'state': 'RUNNING'
            },
            {
                'id': 'projects/swift-demo/buckets/financial-data-prod',
                'type': 'storage.googleapis.com/Bucket',
                'location': 'US',
                'labels': {'environment': 'production', 'classification': 'sensitive'},
                'state': 'ACTIVE'
            },
            {
                'id': 'projects/swift-demo/instances/trading-system-1',
                'type': 'compute.googleapis.com/Instance',
                'location': 'us-east1-a',
                'labels': {'environment': 'production', 'tier': 'trading', 'criticality': 'critical'},
                'network_tags': ['trading-system', 'secure'],
                'state': 'RUNNING'
            },
            {
                'id': 'projects/swift-demo/networks/vpc-prod',
                'type': 'compute.googleapis.com/Network',
                'location': 'global',
                'labels': {'environment': 'production'},
                'state': 'ACTIVE'
            }
        ]
    
    def discover_external_exposure(self, domain: str) -> List[Dict]:
        """Discover externally visible assets using Shodan/Censys"""
        exposed_assets = []
        
        # This would integrate with Shodan/Censys APIs
        # For demo, we'll simulate some results
        simulated_exposure = [
            {
                'ip': '203.0.113.1',
                'ports': [80, 443, 22],
                'services': ['http', 'https', 'ssh'],
                'banner': 'nginx/1.18.0',
                'location': 'US',
                'last_seen': datetime.now().isoformat()
            },
            {
                'ip': '203.0.113.10',
                'ports': [443, 8080],
                'services': ['https', 'http-alt'],
                'banner': 'Apache/2.4.41',
                'location': 'US',
                'last_seen': datetime.now().isoformat()
            }
        ]
        
        return simulated_exposure

class RiskAssessmentEngine:
    """AI-powered risk assessment for discovered assets"""
    
    def __init__(self):
        self.risk_weights = {
            'internet_exposure': 0.3,
            'vulnerability_severity': 0.25,
            'threat_context': 0.2,
            'asset_criticality': 0.15,
            'compliance_gap': 0.1
        }
        
    def calculate_exposure_score(self, asset: Dict) -> float:
        """Calculate exposure risk score (0-5)"""
        score = 0
        
        # Internet exposure
        if asset.get('external_ip'):
            score += 3
        if asset.get('open_ports'):
            score += len(asset['open_ports']) * 0.5
            
        # Service exposure
        risky_services = ['ssh', 'rdp', 'ftp', 'telnet']
        for service in asset.get('services', []):
            if service.lower() in risky_services:
                score += 1
                
        return min(score, 5)
    
    def calculate_vulnerability_impact(self, vulnerabilities: List[str]) -> float:
        """Calculate vulnerability impact score"""
        if not vulnerabilities:
            return 0
            
        impact_score = 0
        for vuln in vulnerabilities:
            # Parse CVSS score if available
            if 'CVSS:' in vuln:
                try:
                    cvss = float(vuln.split('CVSS:')[1].split()[0])
                    impact_score += cvss / 10  # Normalize to 0-1
                except:
                    impact_score += 0.5  # Default medium impact
            else:
                impact_score += 0.5
                
        return min(impact_score, 5)
    
    def calculate_threat_context_score(self, threat_data: Dict) -> float:
        """Calculate threat context risk multiplier"""
        score = 1.0  # Base multiplier
        
        if threat_data.get('exploited_in_wild'):
            score *= 2.0
        if threat_data.get('exploit_availability') == 'confirmed':
            score *= 1.5
        if threat_data.get('threat_actors'):
            score *= 1.3
            
        return min(score, 3.0)
    
    def calculate_final_risk_score(self, asset: Dict, vulnerabilities: List[str], 
                                 threat_context: Dict) -> float:
        """Calculate final AI-powered risk score"""
        
        exposure = self.calculate_exposure_score(asset)
        vuln_impact = self.calculate_vulnerability_impact(vulnerabilities)
        threat_multiplier = self.calculate_threat_context_score(threat_context)
        
        # Asset criticality (based on labels/tags)
        criticality = 1.0
        if asset.get('labels', {}).get('environment') == 'production':
            criticality = 2.0
        if asset.get('labels', {}).get('criticality') == 'critical':
            criticality = 2.5
        elif asset.get('labels', {}).get('criticality') == 'high':
            criticality = 2.0
            
        # Final calculation
        base_score = (
            exposure * self.risk_weights['internet_exposure'] +
            vuln_impact * self.risk_weights['vulnerability_severity'] +
            criticality * self.risk_weights['asset_criticality']
        )
        
        final_score = base_score * threat_multiplier
        return min(final_score, 10.0)

class AttackSurfaceEngine:
    """Main engine orchestrating all components"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.threat_intel = ThreatIntelligenceAggregator()
        self.cloud_discovery = CloudAssetDiscovery(config.get('project_id', 'demo-project'))
        self.risk_engine = RiskAssessmentEngine()
        self.db_path = config.get('database_path', 'data/attack_surface.db')
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing results"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                asset_type TEXT,
                risk_score REAL,
                exposure_level INTEGER,
                threat_context TEXT,
                vulnerabilities TEXT,
                last_updated TIMESTAMP,
                raw_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TIMESTAMP,
                total_assets INTEGER,
                high_risk_assets INTEGER,
                critical_findings TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def run_discovery_scan(self) -> Dict:
        """Run complete attack surface discovery"""
        print("🔍 Starting Attack Surface Discovery...")
        
        scan_results = {
            'scan_id': hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            'start_time': datetime.now(),
            'assets': [],
            'high_risk_assets': [],
            'summary': {}
        }
        
        # 1. Cloud Asset Discovery
        print("📡 Discovering cloud assets...")
        cloud_assets = await self.cloud_discovery.discover_gcp_assets()
        
        # 2. External Exposure Discovery
        print("🌐 Scanning external exposure...")
        external_assets = self.cloud_discovery.discover_external_exposure(
            self.config.get('domain', 'swift.com')
        )
        
        # 3. Risk Assessment
        print("🎯 Calculating risk scores...")
        all_assets = cloud_assets + external_assets
        
        for asset in all_assets:
            # Get vulnerabilities (simulated for demo)
            vulnerabilities = self.simulate_vulnerability_scan(asset)
            
            # Get threat context
            threat_context = {}
            for vuln in vulnerabilities:
                if 'CVE-' in vuln:
                    cve_context = self.threat_intel.get_cve_context(vuln)
                    threat_context.update(cve_context)
            
            # Calculate final risk score
            risk_score = self.risk_engine.calculate_final_risk_score(
                asset, vulnerabilities, threat_context
            )
            
            asset_risk = AssetRisk(
                asset_id=asset.get('id', 'unknown'),
                asset_type=asset.get('type', 'unknown'),
                exposure_level=int(self.risk_engine.calculate_exposure_score(asset)),
                threat_context=threat_context,
                vulnerabilities=vulnerabilities,
                risk_score=risk_score,
                last_updated=datetime.now()
            )
            
            scan_results['assets'].append(asset_risk)
            
            if risk_score >= 7.0:
                scan_results['high_risk_assets'].append(asset_risk)
        
        # 4. Store results
        self.store_scan_results(scan_results)
        
        # 5. Generate summary
        scan_results['summary'] = self.generate_summary(scan_results)
        scan_results['end_time'] = datetime.now()
        
        print(f"✅ Scan complete! Found {len(scan_results['high_risk_assets'])} high-risk assets")
        return scan_results
    
    def simulate_vulnerability_scan(self, asset: Dict) -> List[str]:
        """Simulate vulnerability scanning (replace with real scanner integration)"""
        # This would integrate with actual vulnerability scanners
        # For demo purposes, we'll simulate some results
        
        simulated_vulns = []
        
        if 'Instance' in asset.get('type', ''):
            simulated_vulns = [
                'CVE-2021-44228 (Log4j) - CVSS:9.8',
                'CVE-2021-34527 (PrintNightmare) - CVSS:8.8',
                'Outdated OS packages detected'
            ]
        elif 'Bucket' in asset.get('type', ''):
            simulated_vulns = [
                'Public read access enabled',
                'Bucket versioning disabled',
                'Encryption at rest not configured'
            ]
        elif 'trading' in asset.get('id', '').lower():
            simulated_vulns = [
                'CVE-2021-34473 (ProxyShell) - CVSS:8.8',
                'Weak authentication controls',
                'Insufficient audit logging'
            ]
            
        return simulated_vulns
    
    def store_scan_results(self, results: Dict):
        """Store scan results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store scan metadata
        cursor.execute('''
            INSERT INTO scans (scan_date, total_assets, high_risk_assets, critical_findings)
            VALUES (?, ?, ?, ?)
        ''', (
            results['start_time'],
            len(results['assets']),
            len(results['high_risk_assets']),
            json.dumps([asset.asset_id for asset in results['high_risk_assets']])
        ))
        
        # Store individual assets
        for asset in results['assets']:
            cursor.execute('''
                INSERT OR REPLACE INTO assets 
                (id, asset_type, risk_score, exposure_level, threat_context, vulnerabilities, last_updated, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                asset.asset_id,
                asset.asset_type,
                asset.risk_score,
                asset.exposure_level,
                json.dumps(asset.threat_context),
                json.dumps(asset.vulnerabilities),
                asset.last_updated,
                json.dumps(asset.__dict__, default=str)
            ))
        
        conn.commit()
        conn.close()
    
    def generate_summary(self, results: Dict) -> Dict:
        """Generate executive summary of scan results"""
        total_assets = len(results['assets'])
        high_risk = len(results['high_risk_assets'])
        
        risk_distribution = {
            'critical': len([a for a in results['assets'] if a.risk_score >= 8.0]),
            'high': len([a for a in results['assets'] if 6.0 <= a.risk_score < 8.0]),
            'medium': len([a for a in results['assets'] if 4.0 <= a.risk_score < 6.0]),
            'low': len([a for a in results['assets'] if a.risk_score < 4.0])
        }
        
        return {
            'total_assets': total_assets,
            'high_risk_percentage': (high_risk / total_assets * 100) if total_assets > 0 else 0,
            'risk_distribution': risk_distribution,
            'top_threats': self.get_top_threats(results['assets']),
            'recommendations': self.generate_recommendations(results['high_risk_assets'])
        }
    
    def get_top_threats(self, assets: List[AssetRisk]) -> List[str]:
        """Identify top threats across all assets"""
        threat_count = {}
        
        for asset in assets:
            for vuln in asset.vulnerabilities:
                if 'CVE-' in vuln:
                    cve = vuln.split()[0]
                    threat_count[cve] = threat_count.get(cve, 0) + 1
        
        # Return top 5 threats
        return sorted(threat_count.items(), key=lambda x: x[1], reverse=True)[:5]
    
    def generate_recommendations(self, high_risk_assets: List[AssetRisk]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if high_risk_assets:
            recommendations.append(f"Immediately review {len(high_risk_assets)} high-risk assets")
            
        # Asset-specific recommendations
        internet_exposed = [a for a in high_risk_assets if a.exposure_level >= 3]
        if internet_exposed:
            recommendations.append(f"Implement additional controls for {len(internet_exposed)} internet-exposed assets")
        
        # Vulnerability-specific recommendations
        critical_vulns = [a for a in high_risk_assets if any('CVSS:9' in v or 'CVSS:8' in v for v in a.vulnerabilities)]
        if critical_vulns:
            recommendations.append(f"Patch critical vulnerabilities on {len(critical_vulns)} assets")
        
        return recommendations

# Example usage and configuration
def main():
    """Example usage of the Attack Surface Engine"""
    
    config = {
        'project_id': 'demo-project',
        'domain': 'swift.com',
        'database_path': 'data/attack_surface.db'
    }
    
    engine = AttackSurfaceEngine(config)
    
    # Run async scan
    async def run_scan():
        results = await engine.run_discovery_scan()
        
        print("\n📊 ATTACK SURFACE SUMMARY")
        print("=" * 40)
        print(f"Total Assets: {results['summary']['total_assets']}")
        print(f"High Risk: {len(results['high_risk_assets'])}")
        print(f"Risk Distribution: {results['summary']['risk_distribution']}")
        
        if results['high_risk_assets']:
            print("\n🚨 HIGH RISK ASSETS:")
            for asset in results['high_risk_assets'][:5]:  # Show top 5
                print(f"- {asset.asset_id}: Risk Score {asset.risk_score:.1f}")
                
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in results['summary']['recommendations']:
            print(f"- {rec}")
    
    # Run the scan
    asyncio.run(run_scan())

if __name__ == "__main__":
    main()
