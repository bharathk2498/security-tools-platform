#!/usr/bin/env python3
"""
Interactive Security Dashboards for Demo
Creates impressive visualizations for all three tools
"""

import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import json
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityDashboards:
    """Creates interactive dashboards for all security tools"""
    
    def __init__(self, db_path: str = "data/security_tools.db"):
        self.db_path = db_path
        self.app = dash.Dash(__name__, suppress_callback_exceptions=True)
        self.setup_layout()
        self.setup_callbacks()
        
    def generate_sample_data(self):
        """Generate realistic sample data for demonstrations"""
        
        # Attack Surface Sample Data
        attack_surface_data = {
            'assets': [
                {'id': 'web-server-prod-1', 'type': 'Compute Instance', 'risk_score': 8.5, 'exposure': 'High', 'vulnerabilities': 3, 'environment': 'production'},
                {'id': 'trading-system-1', 'type': 'Compute Instance', 'risk_score': 9.2, 'exposure': 'Critical', 'vulnerabilities': 4, 'environment': 'production'},
                {'id': 'database-prod-1', 'type': 'Cloud SQL', 'risk_score': 7.2, 'exposure': 'Medium', 'vulnerabilities': 2, 'environment': 'production'},
                {'id': 'financial-data-bucket', 'type': 'Storage Bucket', 'risk_score': 6.8, 'exposure': 'Medium', 'vulnerabilities': 1, 'environment': 'production'},
                {'id': 'load-balancer-prod', 'type': 'Load Balancer', 'risk_score': 5.5, 'exposure': 'Low', 'vulnerabilities': 0, 'environment': 'production'},
                {'id': 'backup-storage', 'type': 'Storage Bucket', 'risk_score': 4.2, 'exposure': 'Low', 'vulnerabilities': 0, 'environment': 'production'},
                {'id': 'dev-server-1', 'type': 'Compute Instance', 'risk_score': 6.1, 'exposure': 'Medium', 'vulnerabilities': 1, 'environment': 'development'}
            ],
            'risk_trends': [
                {'date': '2024-01-01', 'risk_score': 7.2, 'assets_scanned': 1200, 'threats_detected': 15},
                {'date': '2024-01-02', 'risk_score': 6.8, 'assets_scanned': 1235, 'threats_detected': 12},
                {'date': '2024-01-03', 'risk_score': 7.5, 'assets_scanned': 1247, 'threats_detected': 18},
                {'date': '2024-01-04', 'risk_score': 7.1, 'assets_scanned': 1251, 'threats_detected': 14},
                {'date': '2024-01-05', 'risk_score': 6.9, 'assets_scanned': 1265, 'threats_detected': 11},
                {'date': '2024-01-06', 'risk_score': 7.3, 'assets_scanned': 1270, 'threats_detected': 16},
                {'date': '2024-01-07', 'risk_score': 6.7, 'assets_scanned': 1275, 'threats_detected': 9}
            ],
            'threat_intelligence': [
                {'threat': 'CVE-2021-44228 (Log4j RCE)', 'assets_affected': 15, 'severity': 'Critical', 'exploited_wild': True},
                {'threat': 'CVE-2021-34527 (PrintNightmare)', 'assets_affected': 8, 'severity': 'High', 'exploited_wild': True},
                {'threat': 'CVE-2021-34473 (ProxyShell)', 'assets_affected': 3, 'severity': 'High', 'exploited_wild': False},
                {'threat': 'CVE-2022-22965 (Spring4Shell)', 'assets_affected': 5, 'severity': 'Medium', 'exploited_wild': False},
                {'threat': 'Weak SSH Configuration', 'assets_affected': 12, 'severity': 'Medium', 'exploited_wild': False}
            ]
        }
        
        # Chronicle SIEM Sample Data
        chronicle_data = {
            'alerts': [
                {'time': '10:30', 'rule': 'Suspicious Login from TOR', 'severity': 'High', 'confidence': 0.92, 'status': 'Triaged', 'user': 'trading_admin'},
                {'time': '11:15', 'rule': 'Privilege Escalation', 'severity': 'Critical', 'confidence': 0.88, 'status': 'Investigating', 'user': 'payment_processor'},
                {'time': '12:00', 'rule': 'Data Exfiltration', 'severity': 'Critical', 'confidence': 0.95, 'status': 'Contained', 'user': 'back_office'},
                {'time': '12:30', 'rule': 'Malware Detection', 'severity': 'High', 'confidence': 0.82, 'status': 'Resolved', 'user': 'workstation_user'},
                {'time': '13:45', 'rule': 'Lateral Movement', 'severity': 'Medium', 'confidence': 0.75, 'status': 'False Positive', 'user': 'service_account'},
                {'time': '14:20', 'rule': 'Unusual API Access', 'severity': 'Medium', 'confidence': 0.68, 'status': 'Triaged', 'user': 'api_service'},
                {'time': '15:10', 'rule': 'Failed Login Spikes', 'severity': 'Low', 'confidence': 0.45, 'status': 'False Positive', 'user': 'multiple_users'}
            ],
            'ml_performance': {
                'accuracy': 94.5,
                'false_positive_rate': 12.8,
                'mean_response_time': 8.2,
                'alerts_processed_today': 156,
                'precision': 0.89,
                'recall': 0.92,
                'f1_score': 0.91
            },
            'threat_actors': [
                {'actor': 'APT29 (Cozy Bear)', 'campaigns': 3, 'last_seen': '2024-01-10', 'targeting': 'Financial Services'},
                {'actor': 'Lazarus Group', 'campaigns': 2, 'last_seen': '2024-01-08', 'targeting': 'Cryptocurrency'},
                {'actor': 'FIN7', 'campaigns': 1, 'last_seen': '2024-01-05', 'targeting': 'Payment Systems'},
                {'actor': 'Carbanak', 'campaigns': 1, 'last_seen': '2024-01-03', 'targeting': 'Banking'}
            ],
            'response_metrics': [
                {'date': '2024-01-01', 'automated_responses': 45, 'manual_responses': 12, 'avg_response_time': 8.5},
                {'date': '2024-01-02', 'automated_responses': 52, 'manual_responses': 8, 'avg_response_time': 7.2},
                {'date': '2024-01-03', 'automated_responses': 48, 'manual_responses': 15, 'avg_response_time': 9.1},
                {'date': '2024-01-04', 'automated_responses': 41, 'manual_responses': 9, 'avg_response_time': 6.8},
                {'date': '2024-01-05', 'automated_responses': 55, 'manual_responses': 11, 'avg_response_time': 7.5}
            ]
        }
        
        # NIST Compliance Sample Data
        compliance_data = {
            'controls': [
                {'family': 'AC', 'name': 'Access Control', 'compliant': 2, 'total': 3, 'score': 67, 'trend': 'improving'},
                {'family': 'AU', 'name': 'Audit & Accountability', 'compliant': 2, 'total': 2, 'score': 100, 'trend': 'stable'},
                {'family': 'SC', 'name': 'System Protection', 'compliant': 1, 'total': 2, 'score': 50, 'trend': 'needs_attention'},
                {'family': 'IA', 'name': 'Identification & Auth', 'compliant': 2, 'total': 2, 'score': 100, 'trend': 'stable'},
                {'family': 'CM', 'name': 'Configuration Mgmt', 'compliant': 0, 'total': 0, 'score': 0, 'trend': 'not_implemented'},
                {'family': 'CP', 'name': 'Contingency Planning', 'compliant': 0, 'total': 0, 'score': 0, 'trend': 'not_implemented'},
                {'family': 'IR', 'name': 'Incident Response', 'compliant': 0, 'total': 0, 'score': 0, 'trend': 'not_implemented'},
                {'family': 'SI', 'name': 'System Integrity', 'compliant': 0, 'total': 0, 'score': 0, 'trend': 'not_implemented'}
            ],
            'remediation_plan': [
                {'control': 'AC-2', 'title': 'Account Management', 'priority': 'High', 'effort': 'Medium', 'status': 'In Progress', 'score': 65},
                {'control': 'SC-7', 'title': 'Boundary Protection', 'priority': 'High', 'effort': 'Low', 'status': 'Planned', 'score': 45},
                {'control': 'AC-6', 'title': 'Least Privilege', 'priority': 'Medium', 'effort': 'High', 'status': 'Planned', 'score': 70},
                {'control': 'SC-8', 'title': 'Transmission Protection', 'priority': 'Medium', 'effort': 'Medium', 'status': 'Planned', 'score': 55},
                {'control': 'AC-3', 'title': 'Access Enforcement', 'priority': 'Low', 'effort': 'Low', 'status': 'Completed', 'score': 92}
            ],
            'compliance_history': [
                {'date': '2024-01-01', 'score': 82.5, 'controls_compliant': 6, 'total_controls': 9},
                {'date': '2024-01-02', 'score': 84.1, 'controls_compliant': 6, 'total_controls': 9},
                {'date': '2024-01-03', 'score': 85.8, 'controls_compliant': 7, 'total_controls': 9},
                {'date': '2024-01-04', 'score': 87.2, 'controls_compliant': 7, 'total_controls': 9},
                {'date': '2024-01-05', 'score': 87.5, 'controls_compliant': 7, 'total_controls': 9}
            ]
        }
        
        return attack_surface_data, chronicle_data, compliance_data
    
    def setup_layout(self):
        """Setup the main dashboard layout"""
        
        self.app.layout = html.Div([
            dcc.Location(id='url', refresh=False),
            html.Div(id='page-content')
        ])
        
    def create_attack_surface_layout(self):
        """Create Attack Surface Discovery dashboard"""
        
        attack_data, _, _ = self.generate_sample_data()
        
        # Convert to DataFrames for easier plotting
        assets_df = pd.DataFrame(attack_data['assets'])
        trends_df = pd.DataFrame(attack_data['risk_trends'])
        threats_df = pd.DataFrame(attack_data['threat_intelligence'])
        
        # Create visualizations
        risk_score_chart = px.scatter(
            assets_df, 
            x='type', 
            y='risk_score', 
            size='vulnerabilities',
            color='exposure',
            hover_data=['id', 'environment'],
            title="Asset Risk Assessment by Type",
            color_discrete_map={'Critical': '#8B0000', 'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#27ae60'},
            size_max=20
        )
        risk_score_chart.update_layout(height=400)
        
        trend_chart = px.line(
            trends_df,
            x='date',
            y=['risk_score', 'threats_detected'],
            title="Risk Score and Threat Detection Trends",
            markers=True
        )
        trend_chart.update_layout(height=400)
        
        threat_chart = px.bar(
            threats_df,
            x='threat',
            y='assets_affected',
            color='severity',
            title="Active Threats by Impact",
            color_discrete_map={'Critical': '#c0392b', 'High': '#e67e22', 'Medium': '#f39c12', 'Low': '#27ae60'}
        )
        threat_chart.update_layout(height=400, xaxis_tickangle=-45)
        
        # Risk distribution pie chart
        risk_dist = assets_df['exposure'].value_counts()
        risk_pie = px.pie(
            values=risk_dist.values,
            names=risk_dist.index,
            title="Risk Distribution",
            color_discrete_map={'Critical': '#8B0000', 'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#27ae60'}
        )
        risk_pie.update_layout(height=400)
        
        layout = html.Div([
            html.H1("🔍 Attack Surface Discovery Engine", className="header-title"),
            html.Div([
                html.Div([
                    html.H3("📊 Key Metrics"),
                    html.Div([
                        html.Div([
                            html.H2("1,275", className="metric-value"),
                            html.P("Total Assets", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("23", className="metric-value"),
                            html.P("High Risk Assets", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("95.2%", className="metric-value"),
                            html.P("Discovery Accuracy", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("7.1", className="metric-value"),
                            html.P("Avg Risk Score", className="metric-label")
                        ], className="metric-card"),
                    ], className="metrics-grid")
                ], className="section"),
                
                html.Div([
                    html.Div([
                        html.H3("🎯 Asset Risk Analysis"),
                        dcc.Graph(figure=risk_score_chart)
                    ], className="half-section"),
                    html.Div([
                        html.H3("📊 Risk Distribution"),
                        dcc.Graph(figure=risk_pie)
                    ], className="half-section")
                ], className="section-row"),
                
                html.Div([
                    html.H3("📈 Risk and Threat Trends"),
                    dcc.Graph(figure=trend_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("⚠️ Active Threat Intelligence"),
                    dcc.Graph(figure=threat_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("🔍 Asset Inventory"),
                    dash_table.DataTable(
                        data=assets_df.to_dict('records'),
                        columns=[
                            {'name': 'Asset ID', 'id': 'id'},
                            {'name': 'Type', 'id': 'type'},
                            {'name': 'Environment', 'id': 'environment'},
                            {'name': 'Risk Score', 'id': 'risk_score', 'type': 'numeric', 'format': {'specifier': '.1f'}},
                            {'name': 'Exposure', 'id': 'exposure'},
                            {'name': 'Vulnerabilities', 'id': 'vulnerabilities'}
                        ],
                        style_cell={'textAlign': 'left', 'padding': '10px'},
                        style_header={'backgroundColor': '#3498db', 'color': 'white', 'fontWeight': 'bold'},
                        style_data_conditional=[
                            {
                                'if': {'filter_query': '{risk_score} > 8'},
                                'backgroundColor': '#fadbd8',
                                'color': 'black',
                            },
                            {
                                'if': {'filter_query': '{risk_score} > 7 && {risk_score} <= 8'},
                                'backgroundColor': '#fdeaa7',
                                'color': 'black',
                            }
                        ],
                        sort_action="native",
                        filter_action="native"
                    )
                ], className="section")
            ])
        ])
        
        return layout
    
    def create_chronicle_layout(self):
        """Create Chronicle SIEM Orchestration dashboard"""
        
        _, chronicle_data, _ = self.generate_sample_data()
        
        alerts_df = pd.DataFrame(chronicle_data['alerts'])
        response_df = pd.DataFrame(chronicle_data['response_metrics'])
        
        # ML Performance Gauge
        ml_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = chronicle_data['ml_performance']['accuracy'],
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "ML Model Accuracy (%)"},
            delta = {'reference': 90},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 70], 'color': "lightgray"},
                    {'range': [70, 90], 'color': "#f39c12"},
                    {'range': [90, 100], 'color': "#27ae60"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 95
                }
            }
        ))
        ml_gauge.update_layout(height=300)
        
        # Alert Status Distribution
        alert_status_chart = px.pie(
            alerts_df,
            names='status',
            title="Alert Status Distribution",
            color_discrete_map={
                'Triaged': '#3498db',
                'Investigating': '#f39c12', 
                'Contained': '#27ae60',
                'Resolved': '#2ecc71',
                'False Positive': '#95a5a6'
            }
        )
        alert_status_chart.update_layout(height=300)
        
        # Confidence vs Severity Scatter
        confidence_chart = px.scatter(
            alerts_df,
            x='confidence',
            y='severity',
            size=[10]*len(alerts_df),
            hover_data=['rule', 'time', 'user'],
            title="Alert Confidence vs Severity",
            color='status',
            color_discrete_map={
                'Triaged': '#3498db',
                'Investigating': '#f39c12', 
                'Contained': '#27ae60',
                'Resolved': '#2ecc71',
                'False Positive': '#95a5a6'
            }
        )
        confidence_chart.update_layout(height=400)
        
        # Response Time Trends
        response_chart = px.bar(
            response_df,
            x='date',
            y=['automated_responses', 'manual_responses'],
            title="Automated vs Manual Response Trends",
            barmode='stack'
        )
        response_chart.update_layout(height=400)
        
        layout = html.Div([
            html.H1("🎯 Chronicle SIEM Orchestration Platform", className="header-title"),
            html.Div([
                html.Div([
                    html.H3("📊 Real-time Performance Metrics"),
                    html.Div([
                        html.Div([
                            html.H2("156", className="metric-value"),
                            html.P("Alerts Today", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("94.5%", className="metric-value"),
                            html.P("ML Accuracy", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("12.8%", className="metric-value"),
                            html.P("False Positive Rate", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("8.2min", className="metric-value"),
                            html.P("Mean Response Time", className="metric-label")
                        ], className="metric-card"),
                    ], className="metrics-grid")
                ], className="section"),
                
                html.Div([
                    html.Div([
                        html.H3("🤖 ML Model Performance"),
                        dcc.Graph(figure=ml_gauge)
                    ], className="half-section"),
                    html.Div([
                        html.H3("📊 Alert Status Distribution"),
                        dcc.Graph(figure=alert_status_chart)
                    ], className="half-section")
                ], className="section-row"),
                
                html.Div([
                    html.H3("🎯 Confidence vs Severity Analysis"),
                    dcc.Graph(figure=confidence_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("🚀 Response Automation Trends"),
                    dcc.Graph(figure=response_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("🚨 Recent Alert Analysis"),
                    dash_table.DataTable(
                        data=alerts_df.to_dict('records'),
                        columns=[
                            {'name': 'Time', 'id': 'time'},
                            {'name': 'Rule', 'id': 'rule'},
                            {'name': 'Severity', 'id': 'severity'},
                            {'name': 'User', 'id': 'user'},
                            {'name': 'Confidence', 'id': 'confidence', 'type': 'numeric', 'format': {'specifier': '.2f'}},
                            {'name': 'Status', 'id': 'status'}
                        ],
                        style_cell={'textAlign': 'left', 'padding': '10px'},
                        style_header={'backgroundColor': '#2c3e50', 'color': 'white', 'fontWeight': 'bold'},
                        style_data_conditional=[
                            {
                                'if': {'filter_query': '{severity} = Critical'},
                                'backgroundColor': '#fadbd8',
                                'color': 'black',
                            },
                            {
                                'if': {'filter_query': '{confidence} > 0.9'},
                                'backgroundColor': '#d5f4e6',
                                'color': 'black',
                            }
                        ],
                        sort_action="native"
                    )
                ], className="section"),
                
                html.Div([
                    html.H3("🎭 Threat Actor Intelligence"),
                    dash_table.DataTable(
                        data=chronicle_data['threat_actors'],
                        columns=[
                            {'name': 'Threat Actor', 'id': 'actor'},
                            {'name': 'Active Campaigns', 'id': 'campaigns'},
                            {'name': 'Primary Targeting', 'id': 'targeting'},
                            {'name': 'Last Seen', 'id': 'last_seen'}
                        ],
                        style_cell={'textAlign': 'left', 'padding': '10px'},
                        style_header={'backgroundColor': '#8B0000', 'color': 'white', 'fontWeight': 'bold'}
                    )
                ], className="section")
            ])
        ])
        
        return layout
    
    def create_compliance_layout(self):
        """Create NIST Compliance dashboard"""
        
        _, _, compliance_data = self.generate_sample_data()
        
        controls_df = pd.DataFrame(compliance_data['controls'])
        remediation_df = pd.DataFrame(compliance_data['remediation_plan'])
        history_df = pd.DataFrame(compliance_data['compliance_history'])
        
        # Filter out unimplemented controls for main charts
        implemented_controls = controls_df[controls_df['total'] > 0]
        
        # Overall compliance score gauge
        overall_score = 77.8  # Based on implemented controls
        compliance_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = overall_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Overall Compliance Score (%)"},
            delta = {'reference': 80},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkgreen"},
                'steps': [
                    {'range': [0, 60], 'color': "lightgray"},
                    {'range': [60, 80], 'color': "#f39c12"},
                    {'range': [80, 100], 'color': "#27ae60"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        compliance_gauge.update_layout(height=300)
        
        # Control family compliance
        family_chart = px.bar(
            implemented_controls,
            x='family',
            y='score',
            color='score',
            title="Compliance by Control Family (Implemented Controls)",
            color_continuous_scale='RdYlGn',
            text='score',
            hover_data=['name', 'compliant', 'total']
        )
        family_chart.update_traces(texttemplate='%{text}%', textposition='outside')
        family_chart.update_layout(height=400)
        
        # Compliance trends
        trend_chart = px.line(
            history_df,
            x='date',
            y='score',
            title="Compliance Score Trends",
            markers=True
        )
        trend_chart.add_scatter(
            x=history_df['date'],
            y=history_df['controls_compliant']/history_df['total_controls']*100,
            mode='lines+markers',
            name='Controls Compliant %',
            line=dict(dash='dash')
        )
        trend_chart.update_layout(height=400)
        
        # Remediation priority matrix
        remediation_chart = px.scatter(
            remediation_df,
            x='effort',
            y='priority',
            size='score',
            hover_data=['control', 'title'],
            title="Remediation Priority Matrix",
            color='status',
            size_max=20
        )
        remediation_chart.update_layout(height=400)
        
        layout = html.Div([
            html.H1("📋 NIST 800-53 Compliance Framework", className="header-title"),
            html.Div([
                html.Div([
                    html.H3("📊 Compliance Overview"),
                    html.Div([
                        html.Div([
                            html.H2("9", className="metric-value"),
                            html.P("Total Controls", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("7", className="metric-value"),
                            html.P("Compliant Controls", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("77.8%", className="metric-value"),
                            html.P("Overall Score", className="metric-label")
                        ], className="metric-card"),
                        html.Div([
                            html.H2("4", className="metric-value"),
                            html.P("Auto-Remediated", className="metric-label")
                        ], className="metric-card"),
                    ], className="metrics-grid")
                ], className="section"),
                
                html.Div([
                    html.Div([
                        html.H3("🎯 Overall Compliance Score"),
                        dcc.Graph(figure=compliance_gauge)
                    ], className="half-section"),
                    html.Div([
                        html.H3("📊 Compliance by Family"),
                        dcc.Graph(figure=family_chart)
                    ], className="half-section")
                ], className="section-row"),
                
                html.Div([
                    html.H3("📈 Compliance Score Trends"),
                    dcc.Graph(figure=trend_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("🔧 Control Family Status"),
                    dash_table.DataTable(
                        data=controls_df.to_dict('records'),
                        columns=[
                            {'name': 'Family', 'id': 'family'},
                            {'name': 'Name', 'id': 'name'},
                            {'name': 'Compliant', 'id': 'compliant'},
                            {'name': 'Total', 'id': 'total'},
                            {'name': 'Score (%)', 'id': 'score'},
                            {'name': 'Trend', 'id': 'trend'}
                        ],
                        style_cell={'textAlign': 'left', 'padding': '10px'},
                        style_header={'backgroundColor': '#34495e', 'color': 'white', 'fontWeight': 'bold'},
                        style_data_conditional=[
                            {
                                'if': {'filter_query': '{score} < 70 && {total} > 0'},
                                'backgroundColor': '#fadbd8',
                                'color': 'black',
                            },
                            {
                                'if': {'filter_query': '{score} >= 90'},
                                'backgroundColor': '#d5f4e6',
                                'color': 'black',
                            },
                            {
                                'if': {'filter_query': '{total} = 0'},
                                'backgroundColor': '#f8f9fa',
                                'color': '#6c757d',
                            }
                        ],
                        sort_action="native"
                    )
                ], className="section"),
                
                html.Div([
                    html.H3("🛠️ Remediation Plan"),
                    dcc.Graph(figure=remediation_chart)
                ], className="section"),
                
                html.Div([
                    html.H3("📋 Remediation Action Items"),
                    dash_table.DataTable(
                        data=remediation_df.to_dict('records'),
                        columns=[
                            {'name': 'Control', 'id': 'control'},
                            {'name': 'Title', 'id': 'title'},
                            {'name': 'Priority', 'id': 'priority'},
                            {'name': 'Effort', 'id': 'effort'},
                            {'name': 'Current Score', 'id': 'score'},
                            {'name': 'Status', 'id': 'status'}
                        ],
                        style_cell={'textAlign': 'left', 'padding': '10px'},
                        style_header={'backgroundColor': '#7B68EE', 'color': 'white', 'fontWeight': 'bold'},
                        style_data_conditional=[
                            {
                                'if': {'filter_query': '{priority} = High'},
                                'backgroundColor': '#fadbd8',
                                'color': 'black',
                            },
                            {
                                'if': {'filter_query': '{status} = Completed'},
                                'backgroundColor': '#d5f4e6',
                                'color': 'black',
                            }
                        ],
                        sort_action="native"
                    )
                ], className="section")
            ])
        ])
        
        return layout
    
    def create_main_layout(self):
        """Create main navigation dashboard"""
        
        layout = html.Div([
            html.H1("🛡️ Security Tools Demo Platform", className="main-header"),
            html.P("Comprehensive Security Automation & Compliance Management", className="main-subtitle"),
            html.P(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", className="timestamp"),
            
            html.Div([
                html.Div([
                    html.H3("🔍 Attack Surface Discovery"),
                    html.P("AI-powered asset discovery with threat intelligence correlation and dynamic risk assessment"),
                    html.Div([
                        html.Span("Status: ", className="status-label"),
                        html.Span("Online", className="status-online"),
                        html.Br(),
                        html.Span("Last Scan: ", className="status-label"),
                        html.Span("2 minutes ago", className="status-info")
                    ]),
                    html.A("View Dashboard", href="/attack-surface", className="dashboard-link")
                ], className="tool-card"),
                
                html.Div([
                    html.H3("🎯 Chronicle SIEM Orchestration"),
                    html.P("ML-based alert triage with automated incident response and threat actor correlation"),
                    html.Div([
                        html.Span("Status: ", className="status-label"),
                        html.Span("Processing", className="status-processing"),
                        html.Br(),
                        html.Span("Alerts Today: ", className="status-label"),
                        html.Span("156", className="status-info")
                    ]),
                    html.A("View Dashboard", href="/chronicle", className="dashboard-link")
                ], className="tool-card"),
                
                html.Div([
                    html.H3("📋 NIST Compliance Framework"),
                    html.P("Policy-as-code implementation with automated monitoring and intelligent remediation"),
                    html.Div([
                        html.Span("Status: ", className="status-label"),
                        html.Span("Monitoring", className="status-monitoring"),
                        html.Br(),
                        html.Span("Compliance Score: ", className="status-label"),
                        html.Span("77.8%", className="status-info")
                    ]),
                    html.A("View Dashboard", href="/compliance", className="dashboard-link")
                ], className="tool-card")
            ], className="tools-grid"),
            
            html.Div([
                html.H3("🚀 Platform Overview"),
                html.Div([
                    html.Div([
                        html.H4("System Health"),
                        html.P("All systems operational"),
                        html.P("Uptime: 99.9%")
                    ], className="overview-card"),
                    html.Div([
                        html.H4("Recent Activity"),
                        html.P("156 alerts processed"),
                        html.P("23 high-risk assets identified")
                    ], className="overview-card"),
                    html.Div([
                        html.H4("Automation Status"),
                        html.P("85% automated responses"),
                        html.P("4 controls auto-remediated")
                    ], className="overview-card")
                ], className="overview-grid")
            ], className="overview-section")
        ])
        
        return layout
    
    def setup_callbacks(self):
        """Setup dashboard navigation callbacks"""
        
        @self.app.callback(
            Output('page-content', 'children'),
            [Input('url', 'pathname')]
        )
        def display_page(pathname):
            if pathname == '/attack-surface':
                return self.create_attack_surface_layout()
            elif pathname == '/chronicle':
                return self.create_chronicle_layout()
            elif pathname == '/compliance':
                return self.create_compliance_layout()
            else:
                return self.create_main_layout()
    
    def add_css_styling(self):
        """Add CSS styling to the dashboard"""
        
        self.app.index_string = '''
        <!DOCTYPE html>
        <html>
        <head>
            {%metas%}
            <title>Security Tools Demo Platform</title>
            {%favicon%}
            {%css%}
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }
                .main-header {
                    text-align: center;
                    color: white;
                    margin-bottom: 10px;
                    font-size: 2.5em;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                }
                .main-subtitle {
                    text-align: center;
                    color: #ecf0f1;
                    margin-bottom: 20px;
                    font-size: 1.2em;
                }
                .timestamp {
                    text-align: center;
                    color: #bdc3c7;
                    margin-bottom: 40px;
                    font-style: italic;
                }
                .header-title {
                    color: #2c3e50;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 10px;
                    margin-bottom: 30px;
                    background: white;
                    padding: 20px;
                    border-radius: 10px 10px 0 0;
                    margin: -20px -20px 30px -20px;
                }
                .tools-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                    gap: 25px;
                    margin-bottom: 40px;
                }
                .tool-card {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    backdrop-filter: blur(10px);
                    transition: transform 0.3s ease;
                }
                .tool-card:hover {
                    transform: translateY(-5px);
                }
                .tool-card h3 {
                    color: #2c3e50;
                    margin-top: 0;
                    font-size: 1.4em;
                }
                .dashboard-link {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #3498db, #2980b9);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    margin: 10px 5px;
                    transition: all 0.3s ease;
                    font-weight: bold;
                }
                .dashboard-link:hover {
                    background: linear-gradient(135deg, #2980b9, #1f5582);
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                }
                .metrics-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .metric-card {
                    background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                    padding: 20px;
                    border-radius: 12px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    text-align: center;
                    border-left: 4px solid #3498db;
                }
                .metric-value {
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #2c3e50;
                    margin: 0;
                    text-shadow: 1px 1px 2px rgba(0,0,0,0.1);
                }
                .metric-label {
                    color: #7f8c8d;
                    margin: 5px 0 0 0;
                    font-weight: 500;
                }
                .section {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 8px 25px rgba(0,0,0,0.15);
                    margin-bottom: 25px;
                    backdrop-filter: blur(10px);
                }
                .section-row {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 25px;
                    margin-bottom: 25px;
                }
                .half-section {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 25px;
                    border-radius: 15px;
                    box-shadow: 0 6px 20px rgba(0,0,0,0.1);
                    backdrop-filter: blur(10px);
                }
                .section h3 {
                    margin-top: 0;
                    color: #2c3e50;
                    border-bottom: 2px solid #ecf0f1;
                    padding-bottom: 10px;
                    font-size: 1.3em;
                }
                .overview-section {
                    background: rgba(255, 255, 255, 0.95);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 8px 25px rgba(0,0,0,0.15);
                    backdrop-filter: blur(10px);
                }
                .overview-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }
                .overview-card {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 10px;
                    border-left: 4px solid #27ae60;
                }
                .status-label {
                    font-weight: bold;
                    color: #2c3e50;
                }
                .status-online {
                    color: #27ae60;
                    font-weight: bold;
                }
                .status-processing {
                    color: #f39c12;
                    font-weight: bold;
                }
                .status-monitoring {
                    color: #3498db;
                    font-weight: bold;
                }
                .status-info {
                    color: #7f8c8d;
                }
                @media (max-width: 768px) {
                    .section-row {
                        grid-template-columns: 1fr;
                    }
                    .tools-grid {
                        grid-template-columns: 1fr;
                    }
                    .main-header {
                        font-size: 2em;
                    }
                }
            </style>
        </head>
        <body>
            {%app_entry%}
            <footer>
                {%config%}
                {%scripts%}
                {%renderer%}
            </footer>
        </body>
        </html>
        '''
    
    def run_server(self, debug=True, port=8050):
        """Run the dashboard server"""
        self.add_css_styling()
        print(f"🚀 Starting Security Tools Dashboard on http://localhost:{port}")
        print("📊 Available dashboards:")
        print("   - Main Navigation: http://localhost:8050/")
        print("   - Attack Surface: http://localhost:8050/attack-surface")
        print("   - Chronicle SIEM: http://localhost:8050/chronicle")
        print("   - NIST Compliance: http://localhost:8050/compliance")
        print("\n🎯 Dashboard ready for interview demonstration!")
        
        self.app.run_server(debug=debug, port=port, host='0.0.0.0')

# Create standalone dashboard script
def main():
    """Run the security dashboards"""
    dashboard = SecurityDashboards()
    dashboard.run_server(debug=True, port=8050)

if __name__ == "__main__":
    main()
