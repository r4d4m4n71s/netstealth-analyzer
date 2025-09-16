"""
NetStealth Analyzer - Advanced log analysis for network stealth operations.

This library provides comprehensive analysis capabilities for detecting stealth issues
in network operations, including:

- TLS fingerprint inconsistencies
- Proxy header exposure
- Browser automation detection
- Anti-bot bypass analysis
- IP geolocation verification
- Performance bottleneck identification

Author: NetStealth Contributors
License: MIT
"""

from .core import NetStealthAnalyzer
from .models import (
    AnalysisResult,
    CriticalIssue,
    NetworkHop,
    AnalysisSummary
)

__version__ = "0.1.0"
__author__ = "NetStealth Contributors"
__email__ = "contributors@netstealth.com"
__description__ = "Advanced log analyzer for network stealth operations"

__all__ = [
    # Core analyzer
    "NetStealthAnalyzer",
    
    # Data models
    "AnalysisResult",
    "CriticalIssue", 
    "NetworkHop",
    "AnalysisSummary",
    
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__description__"
]
