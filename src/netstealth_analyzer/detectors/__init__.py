"""
Detection system for NetStealth Analyzer.

This package contains detectors for various stealth-related issues including
TLS fingerprinting, proxy detection, browser automation signatures, and network anomalies.
"""

from .base import IDetector, BaseDetector
from .registry import DetectorRegistry
from .tls import TlsDetector
from .proxy import ProxyDetector
from .browser import BrowserDetector
from .network import NetworkDetector

__all__ = [
    'IDetector',
    'BaseDetector', 
    'DetectorRegistry',
    'TlsDetector',
    'ProxyDetector',
    'BrowserDetector',
    'NetworkDetector',
]
