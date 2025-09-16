"""
Data models for NetStealth Analyzer v2.0.

This package contains all data models used throughout the analyzer,
organized by functional area for better maintainability.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

from .enums import (
    SeverityLevel, RiskLevel, IssueCategory, LogFormat,
    AnalysisStatus, DetectionConfidence
)

from .issues import (
    Issue, IssueEvidence, IssueLocation, IssueMetadata,
    DetectionRule, RemediationSuggestion
)

from .network import (
    NetworkHop, TLSInfo, ConnectionInfo, ProxyInfo,
    NetworkTrace, GeographicInfo
)

from .results import (
    AnalysisResult, AnalysisSummary, PerformanceMetrics,
    ProcessingStats, ExecutionContext
)

from .enums import *
from .issues import *
from .network import *
from .results import *

__all__ = [
    # Enums
    'SeverityLevel', 'RiskLevel', 'IssueCategory', 'LogFormat',
    'AnalysisStatus', 'DetectionConfidence',
    
    # Issues
    'Issue', 'IssueEvidence', 'IssueLocation', 'IssueMetadata',
    'DetectionRule', 'RemediationSuggestion',
    
    # Network
    'NetworkHop', 'TLSInfo', 'ConnectionInfo', 'ProxyInfo',
    'NetworkTrace', 'GeographicInfo',
    
    # Results
    'AnalysisResult', 'AnalysisSummary', 'PerformanceMetrics',
    'ProcessingStats', 'ExecutionContext',
]
