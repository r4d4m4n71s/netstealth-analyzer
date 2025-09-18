"""
Detection system for NetStealth Analyzer.

This package contains detectors for various stealth-related issues including
TLS fingerprinting, proxy detection, browser automation signatures, and network anomalies.
"""

from .base import IDetector, BaseDetector
from .registry import DetectorRegistry

__all__ = [
    'IDetector',
    'BaseDetector', 
    'DetectorRegistry',
]
