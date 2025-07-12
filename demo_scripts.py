#!/usr/bin/env python3
"""
Interview Demo Scripts
Ready-to-run demonstrations for all three security tools
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
import random
from typing import Dict, List
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.layout import Layout
from rich import print as rprint
import click
import sys
import os
from pathlib import Path

# Add source directories to path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir / "attack_surface_engine/src"))
sys.path.append(str(current_dir / "chronicle_orchestration/src"))
sys.path.append(str(current_dir / "nist_compliance/src"))

console = Console()

class InterviewDemo:
    """Complete demo scenarios for the interview"""
    
    def __init__(self):
        self.console = Console()
        self.demo_data = self.load_demo_data()
        
    def load_demo_data(self) -> Dict:
        """Load realistic demo data"""
        return {
            'assets': [
                {'id': 'web-prod-001', 'type': 'GCE Instance', 'risk': 8.5, 'vulnerabilities': ['CVE-2021-44228', 'CVE-2021-34527'], 'environment': 'production'},
                {'id': 'trading-system-1', 'type': 'GCE Instance', 'risk': 9.2, 'vulnerabilities': ['CVE-2021-34473', 'Weak Auth'], 'environment': 'production'},
                {'id': 'db-prod-001', 'type': 'Cloud SQL', 'risk': 7.2, 'vulnerabilities': ['CVE-2021-34473'], 'environment': 'production'},
                {'id': 'financial-data-bucket', 'type': 'GCS Bucket', 'risk': 6.8, 'vulnerabilities': ['Public Access'], 'environment': 'production'},
                {'id': 'lb-external', 'type': 'Load Balancer', 'risk': 5.5, 'vulnerabilities': [], 'environment': 'production'},
                {'id': 'backup-storage', 'type': 'GCS Bucket', 'risk': 4.2, 'vulnerabilities': [], 'environment': 'production'},
            ],
            'alerts': [
                {'id': 'CHR_001', 'rule': 'Suspicious Login from TOR Exit Node', 'severity': 'HIGH', 'confidence': 0.92, 'user': 'trading_admin@swift.com'},
                {'id': 'CHR_002', 'rule': 'Privilege Escalation via Service Account', 'severity': 'CRITICAL', 'confidence': 0.88, 'user': 'payment_processor@swift.com'},
                {'id': 'CHR_003', 'rule': 'Unusual Wire Transfer Data Access', 'severity': 'HIGH', 'confidence': 0.95, 'user': 'back_office@swift.com'},
                {'id': 'CHR_004', 'rule': 'Malware Detection on Trading System', 'severity': 'CRITICAL', 'confidence': 0.89, 'user': 'system'},
                {'id': 'CHR_005', 'rule': 'Lateral Movement Detected', 'severity': 'MEDIUM', 'confidence': 0.76, 'user': 'service_account'},
            ],
            'compliance_controls': [
                {'id': 'AC-2', 'name': 'Account Management', 'status': 'NON_COMPLIANT', 'score': 65, 'family': 'Access Control'},
                {'id': 'AC-3', 'name': 'Access Enforcement', 'status': 'COMPLIANT', 'score': 92, 'family': 'Access Control'},
                {'id': 'AC-6', 'name': 'Least Privilege', 'status': 'PARTIALLY_COMPLIANT', 'score': 75, 'family': 'Access Control'},
                {'id': 'AU-2', 'name': 'Audit Events', 'status': 'COMPLIANT', 'score': 95, 'family': 'Audit & Accountability'},
                {'id': 'AU-3', 'name': 'Audit Content', 'status': 'COMPLIANT', 'score': 88, 'family': 'Audit & Accountability'},
                {'id': 'SC-7', 'name': 'Boundary Protection', 'status': 'PARTIALLY_COMPLIANT', 'score': 78, 'family': 'System Protection'},
                {'id': 'SC-8', 'name': 'Transmission Protection', 'status': 'PARTIALLY_COMPLIANT', 'score': 82, 'family': 'System Protection'},
                {'id': 'IA-2', 'name': 'User Identification', 'status': 'COMPLIANT', 'score': 90, 'family': 'Identification & Auth'},
                {'id': 'IA-5', 'name': 'Authenticator Management', 'status': 'COMPLIANT', 'score': 85, 'family': 'Identification & Auth'},
            ]
        }
    
    async def run_complete_demo(self):
        """Run the complete interview demonstration"""
        console.print(Panel(
            "[bold blue]🛡️  Security Tools Platform - Live Interview Demo[/bold blue]\n"
            "[dim]Demonstrating next-generation security automation and compliance[/dim]",
            title="🎯 SWIFT Security Engineer Interview",
            border_style="blue"
        ))
        
        console.print(f"[dim]Demo started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
        
        # Demo flow for maximum impact
        await self.demo_attack_surface_discovery()
        await self.demo_chronicle_orchestration()
        await self.demo_nist_compliance()
        await self.demo_integration_capabilities()
        
        console.print(Panel(
            "[bold green]✅ Demo Complete![/bold green]\n"
            "[cyan]Ready for technical deep-dive questions![/cyan]",
            title="🎉 Interview Demo Summary",
            border_style="green"
        ))
    
    async def demo_attack_surface_discovery(self):
        """Demo 1: Attack Surface Discovery Engine"""
        console.print(Panel(
            "[bold]🔍 Attack Surface Discovery Engine[/bold]\n"
            "Real-time asset discovery with AI-powered risk assessment and threat correlation",
            title="Demo 1 - Attack Surface Management",
            border_style="cyan"
        ))
        
        # Simulate scanning process with realistic timing
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task1 = progress.add_task("🌐 Discovering cloud assets across GCP, AWS, Azure...", total=None)
            await asyncio.sleep(2.5)
            progress.update(task1, description="✅ Discovered 1,275 assets across multi-cloud infrastructure")
            
            task2 = progress.add_task("
