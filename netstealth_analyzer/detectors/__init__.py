"""
Detection modules for TIDAL Stealth Analyzer.

This package contains specialized detectors that analyze parsed log data
to identify specific types of issues and vulnerabilities.
"""

from .tls import TLSDetector
from .proxy import ProxyDetector
from .browser import BrowserDetector
from .network import NetworkDetector

__all__ = [
    "TLSDetector",
    "ProxyDetector",
    "BrowserDetector",
    "NetworkDetector",
]
