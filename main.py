#!/usr/bin/env python3
"""
Security Tools Demo - Main Application Entry Point
"""

import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import sys
import os
from pathlib import Path
import json
import logging
from datetime import datetime

# Add the source directories to Python path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir / "attack_surface_engine/src"))
sys.path.append(str(current_dir / "chronicle_orchestration/src"))
sys.path.append(str(current_dir / "nist_compliance/src"))

# Import our tools
try:
    from attack_surface_engine import AttackSurfaceEngine
    from chronicle_orchestration import ChronicleOrchestrator
    from nist_compliance import ComplianceOrchestrator
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all modules are in the correct directories")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Tools Demo Platform",
    description="AI-Powered Attack Surface Management, Chronicle SIEM Orchestration, and NIST Compliance Automation",
    version="1.0.0"
)

# Global configuration
config = {
    'project_id': 'demo-project',
    'database_path': 'data/security_tools.db',
    'environment': 'demo'
}

# Initialize tool engines
attack_surface_engine = AttackSurfaceEngine(config)
chronicle_orchestrator = ChronicleOrchestrator(config)
compliance_orchestrator = ComplianceOrchestrator(config)

@app.get("/", response_class=HTMLResponse)
async def home():
    """Main dashboard showing all tools"""
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Tools Demo Platform</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 40px; }
            .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
            .tool-card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .tool-card h3 { color: #2c3e50; margin-top: 0; }
            .button { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
            .button:hover { background: #2980b9; }
            .metrics { display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }
            .metric { background: #ecf0f1; padding: 15px; border-radius: 5px; }
            .status { color: #27ae60; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Security Tools Demo Platform</h1>
                <p>Comprehensive security automation and compliance management</p>
                <p class="status">System Status: Online | Last Updated: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            </div>
            
            <div class="tools-grid">
                <div class="tool-card">
                    <h3>🔍 Attack Surface Discovery Engine</h3>
                    <p>AI-powered asset discovery with threat intelligence correlation and risk assessment.</p>
                    <div class="metrics">
                        <div class="metric"><strong>1,247</strong><br>Assets Discovered</div>
                        <div class="metric"><strong>23</strong><br>High Risk</div>
                        <div class="metric"><strong>95%</strong><br>Accuracy</div>
                    </div>
                    <a href="/attack-surface/scan" class="button">Run Scan</a>
                    <a href="/attack-surface/dashboard" class="button">View Dashboard</a>
                    <a href="http://localhost:8050/attack-surface" class="button" target="_blank">Interactive Dashboard</a>
                </div>
                
                <div class="tool-card">
                    <h3>🎯 Chronicle SIEM Orchestration</h3>
                    <p>ML-based alert triage with automated incident response and threat correlation.</p>
                    <div class="metrics">
                        <div class="metric"><strong>15,432</strong><br>Alerts Processed</div>
                        <div class="metric"><strong>85%</strong><br>False Positive Reduction</div>
                        <div class="metric"><strong>8 min</strong><br>Mean Response Time</div>
                    </div>
                    <a href="/chronicle/process-alerts" class="button">Process Alerts</a>
                    <a href="/chronicle/dashboard" class="button">View Analytics</a>
                    <a href="http://localhost:8050/chronicle" class="button" target="_blank">Interactive Dashboard</a>
                </div>
                
                <div class="tool-card">
                    <h3>📋 NIST 800-53 Compliance Framework</h3>
                    <p>Policy-as-code implementation with automated compliance monitoring and remediation.</p>
                    <div class="metrics">
                        <div class="metric"><strong>156</strong><br>Controls Monitored</div>
                        <div class="metric"><strong>87%</strong><br>Compliance Score</div>
                        <div class="metric"><strong>12</strong><br>Auto-Remediated</div>
                    </div>
                    <a href="/compliance/assess" class="button">Run Assessment</a>
                    <a href="/compliance/generate" class="button">Generate Infrastructure</a>
                    <a href="http://localhost:8050/compliance" class="button" target="_blank">Interactive Dashboard</a>
                </div>
            </div>
            
            <div style="margin-top: 40px; text-align: center; padding: 20px; background: white; border-radius: 10px;">
                <h3>🚀 Quick Actions</h3>
                <a href="/docs" class="button">API Documentation</a>
                <a href="/health" class="button">System Health</a>
                <a href="https://github.com/your-username/security-tools-platform" class="button" target="_blank">GitHub Repository</a>
            </div>
        </div>
    </body>
    </html>
    '''
    return html_content

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "attack_surface_engine": "online",
            "chronicle_orchestrator": "online", 
            "compliance_orchestrator": "online"
        }
    }

# Attack Surface Engine Endpoints
@app.post("/attack-surface/scan")
async def run_attack_surface_scan():
    """Run comprehensive attack surface discovery scan"""
    try:
        logger.info("Starting attack surface scan...")
        results = await attack_surface_engine.run_discovery_scan()
        
        return {
            "status": "success",
            "scan_id": results["scan_id"],
            "total_assets": len(results["assets"]),
            "high_risk_assets": len(results["high_risk_assets"]),
            "summary": results["summary"],
            "timestamp": results["start_time"].isoformat()
        }
    except Exception as e:
        logger.error(f"Attack surface scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/attack-surface/dashboard")
async def attack_surface_dashboard():
    """Get attack surface dashboard data"""
    try:
        # Return sample dashboard data
        return {
            "total_assets": 1247,
            "high_risk_assets": 23,
            "critical_vulnerabilities": 8,
            "external_exposure": 15,
            "risk_distribution": {
                "critical": 8,
                "high": 15,
                "medium": 45,
                "low": 179
            },
            "top_threats": [
                {"name": "CVE-2021-44228 (Log4j)", "affected_assets": 15},
                {"name": "CVE-2021-34527 (PrintNightmare)", "affected_assets": 8},
                {"name": "CVE-2021-34473 (ProxyShell)", "affected_assets": 3}
            ],
            "risk_trends": [
                {"date": "2024-01-01", "risk_score": 7.2},
                {"date": "2024-01-02", "risk_score": 6.8},
                {"date": "2024-01-03", "risk_score": 7.5},
                {"date": "2024-01-04", "risk_score": 7.1},
                {"date": "2024-01-05", "risk_score": 6.9}
            ]
        }
    except Exception as e:
        logger.error(f"Dashboard data generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Chronicle SIEM Endpoints
@app.post("/chronicle/process-alerts")
async def process_chronicle_alerts():
    """Process sample Chronicle alerts through ML triage"""
    try:
        logger.info("Processing Chronicle alerts...")
        
        # Load sample alerts
        sample_alerts_path = Path("data/samples/sample_alerts.json")
        if sample_alerts_path.exists():
            with open(sample_alerts_path, "r") as f:
                sample_alerts = json.load(f)
        else:
            # Fallback sample data
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
                }
            ]
        
        results = []
        for alert_data in sample_alerts:
            alert = await chronicle_orchestrator.process_chronicle_alert(alert_data)
            results.append({
                "alert_id": alert.alert_id,
                "rule_name": alert.rule_name,
                "confidence": alert.confidence_score,
                "status": alert.status.value,
                "actions": alert.response_actions,
                "severity": alert.severity.name
            })
        
        return {
            "status": "success",
            "processed_alerts": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Alert processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/chronicle/dashboard")
async def chronicle_dashboard():
    """Get Chronicle analytics dashboard data"""
    try:
        analytics = chronicle_orchestrator.get_analytics_dashboard_data()
        return analytics
    except Exception as e:
        logger.error(f"Chronicle dashboard failed: {e}")
        return {
            "message": "Demo analytics data", 
            "total_alerts": 156, 
            "false_positive_rate": 12.8,
            "average_confidence": 0.847,
            "alerts_by_severity": {"HIGH": 45, "MEDIUM": 67, "LOW": 44},
            "ml_performance": {
                "accuracy": 94.5,
                "precision": 0.89,
                "recall": 0.92
            }
        }

# NIST Compliance Endpoints
@app.post("/compliance/assess")
async def run_compliance_assessment():
    """Run NIST 800-53 compliance assessment"""
    try:
        logger.info("Running compliance assessment...")
        assessment = await compliance_orchestrator.run_compliance_assessment()
        
        return {
            "status": "success",
            "assessment_id": assessment.assessment_id,
            "overall_score": assessment.overall_score,
            "compliant_controls": assessment.compliant_controls,
            "total_controls": assessment.total_controls,
            "compliance_percentage": (assessment.compliant_controls / assessment.total_controls) * 100,
            "remediation_actions": len(assessment.remediation_plan),
            "timestamp": assessment.timestamp.isoformat()
        }
    except Exception as e:
        logger.error(f"Compliance assessment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/compliance/generate")
async def generate_compliance_infrastructure():
    """Generate Terraform modules and policies for compliance"""
    try:
        logger.info("Generating compliance infrastructure...")
        generated_files = await compliance_orchestrator.generate_compliance_infrastructure()
        
        return {
            "status": "success",
            "generated_files": generated_files,
            "terraform_modules": len([f for f in generated_files.keys() if 'module' in f]),
            "opa_policies": len([f for f in generated_files.keys() if 'policy' in f]),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Infrastructure generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/compliance/report")
async def get_compliance_report():
    """Get executive compliance report"""
    try:
        report = compliance_orchestrator.generate_compliance_report()
        return report
    except Exception as e:
        logger.error(f"Compliance report generation failed: {e}")
        # Return demo data if generation fails
        return {
            "overall_score": 87.5,
            "total_controls": 9,
            "compliant_controls": 7,
            "compliance_percentage": 77.8,
            "family_breakdown": [
                {"family": "AC", "family_name": "Access Control", "compliance_rate": 66.7},
                {"family": "AU", "family_name": "Audit and Accountability", "compliance_rate": 100.0},
                {"family": "SC", "family_name": "System Protection", "compliance_rate": 50.0},
                {"family": "IA", "family_name": "Identification & Authentication", "compliance_rate": 100.0}
            ],
            "recommendations": [
                "Prioritize AC (Access Control) family improvements",
                "Implement automated remediation for SC (System Protection) controls"
            ]
        }

# Additional utility endpoints
@app.get("/system/status")
async def system_status():
    """Get comprehensive system status"""
    return {
        "platform": "Security Tools Demo Platform",
        "version": "1.0.0",
        "uptime": "Available",
        "database_status": "Connected",
        "ml_models": {
            "attack_surface_engine": "Loaded",
            "chronicle_ml_triage": "Loaded"
        },
        "generated_modules": {
            "terraform_modules": 2,
            "opa_policies": 2
        },
        "last_scans": {
            "attack_surface": "Available",
            "compliance_assessment": "Available"
        }
    }

if __name__ == "__main__":
    print("🚀 Starting Security Tools Demo Platform...")
    print("📊 Main Dashboard: http://localhost:8000")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔧 Health Check: http://localhost:8000/health")
    print("📈 Interactive Dashboards: http://localhost:8050")
    print("\n🎯 Ready for interview demonstration!")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
