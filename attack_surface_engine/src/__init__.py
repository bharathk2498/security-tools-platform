#!/usr/bin/env python3
"""
Attack Surface Engine Module
AI-powered asset discovery and risk assessment
"""

from .attack_surface_engine import (
    AttackSurfaceEngine,
    AssetRisk,
    ThreatIntelligenceAggregator,
    CloudAssetDiscovery,
    RiskAssessmentEngine
)

__version__ = "1.0.0"
__author__ = "Bharath Kumar"

__all__ = [
    "AttackSurfaceEngine",
    "AssetRisk", 
    "ThreatIntelligenceAggregator",
    "CloudAssetDiscovery",
    "RiskAssessmentEngine"
]
