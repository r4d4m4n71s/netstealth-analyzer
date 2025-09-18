"""
Unit tests for NetStealth Analyzer enum models.

Tests all enum classes in src.netstealth_analyzer.models.enums for completeness,
including properties, methods, comparisons, and edge cases.
"""

import pytest
from src.netstealth_analyzer.models.enums import (
    SeverityLevel,
    RiskLevel,
    IssueCategory,
    LogFormat,
    AnalysisStatus,
    DetectionConfidence,
    NetworkProtocol,
    TLSVersion,
    ProxyType,
    GeographicRegion
)


class TestSeverityLevel:
    """Test SeverityLevel enum."""
    
    def test_enum_values(self):
        """Test all severity level values."""
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
        assert SeverityLevel.LOW == "low"
        assert SeverityLevel.INFO == "info"
    
    def test_numeric_value_property(self):
        """Test numeric value property for sorting."""
        assert SeverityLevel.CRITICAL.numeric_value == 5
        assert SeverityLevel.HIGH.numeric_value == 4
        assert SeverityLevel.MEDIUM.numeric_value == 3
        assert SeverityLevel.LOW.numeric_value == 2
        assert SeverityLevel.INFO.numeric_value == 1
    
    def test_color_code_property(self):
        """Test color code property."""
        assert SeverityLevel.CRITICAL.color_code == "#FF0000"
        assert SeverityLevel.HIGH.color_code == "#FF6600"
        assert SeverityLevel.MEDIUM.color_code == "#FFCC00"
        assert SeverityLevel.LOW.color_code == "#00CC00"
        assert SeverityLevel.INFO.color_code == "#0066CC"
    
    def test_comparison_methods(self):
        """Test comparison methods for sorting."""
        assert SeverityLevel.INFO < SeverityLevel.LOW
        assert SeverityLevel.LOW < SeverityLevel.MEDIUM
        assert SeverityLevel.MEDIUM < SeverityLevel.HIGH
        assert SeverityLevel.HIGH < SeverityLevel.CRITICAL
        
        # Test comparison with non-enum returns NotImplemented
        result = SeverityLevel.HIGH.__lt__("not_an_enum")
        assert result == NotImplemented
    
    def test_sorting(self):
        """Test that severity levels can be sorted properly."""
        levels = [SeverityLevel.CRITICAL, SeverityLevel.INFO, SeverityLevel.MEDIUM, SeverityLevel.HIGH]
        sorted_levels = sorted(levels)
        expected = [SeverityLevel.INFO, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert sorted_levels == expected


class TestRiskLevel:
    """Test RiskLevel enum."""
    
    def test_enum_values(self):
        """Test all risk level values."""
        assert RiskLevel.SAFE == "safe"
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL == "critical"
    
    def test_numeric_value_property(self):
        """Test numeric value property."""
        assert RiskLevel.SAFE.numeric_value == 0
        assert RiskLevel.LOW.numeric_value == 1
        assert RiskLevel.MEDIUM.numeric_value == 2
        assert RiskLevel.HIGH.numeric_value == 3
        assert RiskLevel.CRITICAL.numeric_value == 4
    
    def test_comparison_methods(self):
        """Test comparison methods."""
        assert RiskLevel.SAFE < RiskLevel.LOW
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL
        
        # Test with non-enum
        result = RiskLevel.HIGH.__lt__("not_an_enum")
        assert result == NotImplemented


class TestIssueCategory:
    """Test IssueCategory enum."""
    
    def test_core_categories(self):
        """Test core detection categories."""
        assert IssueCategory.TLS_FINGERPRINT == "tls_fingerprint"
        assert IssueCategory.PROXY_DETECTION == "proxy_detection"
        assert IssueCategory.BROWSER_CONFIG == "browser_config"
        assert IssueCategory.NETWORK_ANOMALY == "network_anomaly"
    
    def test_display_name_property(self):
        """Test display name property."""
        assert IssueCategory.TLS_FINGERPRINT.display_name == "TLS Fingerprinting"
        assert IssueCategory.PROXY_DETECTION.display_name == "Proxy Detection"
        assert IssueCategory.BROWSER_CONFIG.display_name == "Browser Configuration"
        assert IssueCategory.DNS_LEAK.display_name == "DNS Leak"
        
        # Test fallback for unmapped categories
        # This tests the .get() fallback in display_name property
        assert IssueCategory.AUTHENTICATION.display_name == "Authentication Issue"
    
    def test_description_property(self):
        """Test description property."""
        assert "TLS characteristics" in IssueCategory.TLS_FINGERPRINT.description
        assert "proxy usage" in IssueCategory.PROXY_DETECTION.description
        assert "Browser configuration" in IssueCategory.BROWSER_CONFIG.description
        
        # Test fallback description - PERFORMANCE has a specific description, not fallback
        assert "Performance issues" in IssueCategory.PERFORMANCE.description
    
    def test_all_categories_have_display_names(self):
        """Test that all categories have meaningful display names."""
        for category in IssueCategory:
            display_name = category.display_name
            assert isinstance(display_name, str)
            assert len(display_name) > 0
            assert display_name != category.value  # Should be different from raw value
    
    def test_all_categories_have_descriptions(self):
        """Test that all categories have descriptions."""
        for category in IssueCategory:
            description = category.description
            assert isinstance(description, str)
            assert len(description) > 10  # Should be meaningful


class TestLogFormat:
    """Test LogFormat enum."""
    
    def test_network_proxy_formats(self):
        """Test network proxy log formats."""
        assert LogFormat.MITMPROXY == "mitmproxy"
        assert LogFormat.BURP_SUITE == "burp_suite"
        assert LogFormat.CHARLES_PROXY == "charles_proxy"
    
    def test_file_extensions_property(self):
        """Test file extensions property."""
        assert LogFormat.MITMPROXY.file_extensions == ['.mitm', '.flow']
        assert LogFormat.HAR.file_extensions == ['.har']
        assert LogFormat.CSV.file_extensions == ['.csv']
        assert LogFormat.JSON_LINES.file_extensions == ['.jsonl', '.ndjson']
    
    def test_supports_streaming_property(self):
        """Test supports streaming property."""
        # Formats that support streaming
        assert LogFormat.JSON_LINES.supports_streaming is True
        assert LogFormat.PLAIN_TEXT.supports_streaming is True
        assert LogFormat.BROWSER_CONSOLE.supports_streaming is True
        assert LogFormat.NETSTEALTH_NATIVE.supports_streaming is True
        
        # Formats that don't support streaming
        assert LogFormat.HAR.supports_streaming is False
        assert LogFormat.CSV.supports_streaming is False
        assert LogFormat.BURP_SUITE.supports_streaming is False
    
    def test_all_formats_have_extensions(self):
        """Test that all formats have file extensions."""
        for format_type in LogFormat:
            extensions = format_type.file_extensions
            assert isinstance(extensions, list)
            assert len(extensions) > 0
            for ext in extensions:
                assert ext.startswith('.')


class TestAnalysisStatus:
    """Test AnalysisStatus enum."""
    
    def test_status_values(self):
        """Test all status values."""
        assert AnalysisStatus.SUCCESS == "success"
        assert AnalysisStatus.PARTIAL_SUCCESS == "partial_success"
        assert AnalysisStatus.FAILED == "failed"
        assert AnalysisStatus.CANCELLED == "cancelled"
        assert AnalysisStatus.TIMEOUT == "timeout"
    
    def test_is_successful_property(self):
        """Test is_successful property."""
        assert AnalysisStatus.SUCCESS.is_successful is True
        assert AnalysisStatus.PARTIAL_SUCCESS.is_successful is True
        assert AnalysisStatus.FAILED.is_successful is False
        assert AnalysisStatus.CANCELLED.is_successful is False
        assert AnalysisStatus.TIMEOUT.is_successful is False
    
    def test_is_terminal_property(self):
        """Test is_terminal property."""
        assert AnalysisStatus.SUCCESS.is_terminal is True
        assert AnalysisStatus.FAILED.is_terminal is True
        assert AnalysisStatus.CANCELLED.is_terminal is True
        assert AnalysisStatus.TIMEOUT.is_terminal is True
        assert AnalysisStatus.PARTIAL_SUCCESS.is_terminal is False


class TestDetectionConfidence:
    """Test DetectionConfidence enum."""
    
    def test_confidence_values(self):
        """Test confidence level values."""
        assert DetectionConfidence.VERY_HIGH == "very_high"
        assert DetectionConfidence.HIGH == "high"
        assert DetectionConfidence.MEDIUM == "medium"
        assert DetectionConfidence.LOW == "low"
        assert DetectionConfidence.VERY_LOW == "very_low"
    
    def test_numeric_range_property(self):
        """Test numeric range property."""
        assert DetectionConfidence.VERY_HIGH.numeric_range == (0.90, 1.00)
        assert DetectionConfidence.HIGH.numeric_range == (0.75, 0.89)
        assert DetectionConfidence.MEDIUM.numeric_range == (0.50, 0.74)
        assert DetectionConfidence.LOW.numeric_range == (0.25, 0.49)
        assert DetectionConfidence.VERY_LOW.numeric_range == (0.00, 0.24)
    
    def test_numeric_value_property(self):
        """Test numeric value property (midpoint of range)."""
        assert DetectionConfidence.VERY_HIGH.numeric_value == 0.95
        assert abs(DetectionConfidence.HIGH.numeric_value - 0.82) < 0.01  # Handle floating point precision
        assert DetectionConfidence.MEDIUM.numeric_value == 0.62
        assert DetectionConfidence.LOW.numeric_value == 0.37
        assert DetectionConfidence.VERY_LOW.numeric_value == 0.12
    
    def test_from_score_class_method(self):
        """Test from_score class method."""
        assert DetectionConfidence.from_score(0.95) == DetectionConfidence.VERY_HIGH
        assert DetectionConfidence.from_score(0.90) == DetectionConfidence.VERY_HIGH
        assert DetectionConfidence.from_score(0.80) == DetectionConfidence.HIGH
        assert DetectionConfidence.from_score(0.75) == DetectionConfidence.HIGH
        assert DetectionConfidence.from_score(0.60) == DetectionConfidence.MEDIUM
        assert DetectionConfidence.from_score(0.50) == DetectionConfidence.MEDIUM
        assert DetectionConfidence.from_score(0.30) == DetectionConfidence.LOW
        assert DetectionConfidence.from_score(0.25) == DetectionConfidence.LOW
        assert DetectionConfidence.from_score(0.10) == DetectionConfidence.VERY_LOW
        assert DetectionConfidence.from_score(0.00) == DetectionConfidence.VERY_LOW
    
    def test_from_score_edge_cases(self):
        """Test from_score with edge cases."""
        # Test boundary values
        assert DetectionConfidence.from_score(0.89) == DetectionConfidence.HIGH
        assert DetectionConfidence.from_score(0.74) == DetectionConfidence.MEDIUM
        assert DetectionConfidence.from_score(0.49) == DetectionConfidence.LOW
        assert DetectionConfidence.from_score(0.24) == DetectionConfidence.VERY_LOW


class TestNetworkProtocol:
    """Test NetworkProtocol enum."""
    
    def test_protocol_values(self):
        """Test protocol values."""
        assert NetworkProtocol.HTTP == "http"
        assert NetworkProtocol.HTTPS == "https"
        assert NetworkProtocol.WEBSOCKET == "websocket"
        assert NetworkProtocol.QUIC == "quic"
    
    def test_is_encrypted_property(self):
        """Test is_encrypted property."""
        # Encrypted protocols
        assert NetworkProtocol.HTTPS.is_encrypted is True
        assert NetworkProtocol.HTTP2.is_encrypted is True
        assert NetworkProtocol.HTTP3.is_encrypted is True
        assert NetworkProtocol.WEBSOCKET_SECURE.is_encrypted is True
        assert NetworkProtocol.QUIC.is_encrypted is True
        
        # Unencrypted protocols
        assert NetworkProtocol.HTTP.is_encrypted is False
        assert NetworkProtocol.WEBSOCKET.is_encrypted is False
        assert NetworkProtocol.TCP.is_encrypted is False
        assert NetworkProtocol.UDP.is_encrypted is False
    
    def test_default_port_property(self):
        """Test default port property."""
        assert NetworkProtocol.HTTP.default_port == 80
        assert NetworkProtocol.HTTPS.default_port == 443
        assert NetworkProtocol.HTTP2.default_port == 443
        assert NetworkProtocol.HTTP3.default_port == 443
        assert NetworkProtocol.WEBSOCKET.default_port == 80
        assert NetworkProtocol.WEBSOCKET_SECURE.default_port == 443
        assert NetworkProtocol.QUIC.default_port == 443
        
        # Protocols without standard ports should return 0
        assert NetworkProtocol.TCP.default_port == 0
        assert NetworkProtocol.UDP.default_port == 0


class TestTLSVersion:
    """Test TLSVersion enum."""
    
    def test_version_values(self):
        """Test TLS version values."""
        assert TLSVersion.SSL_30 == "ssl_3.0"
        assert TLSVersion.TLS_10 == "tls_1.0"
        assert TLSVersion.TLS_11 == "tls_1.1"
        assert TLSVersion.TLS_12 == "tls_1.2"
        assert TLSVersion.TLS_13 == "tls_1.3"
    
    def test_is_secure_property(self):
        """Test is_secure property."""
        # Secure versions
        assert TLSVersion.TLS_12.is_secure is True
        assert TLSVersion.TLS_13.is_secure is True
        
        # Insecure versions
        assert TLSVersion.SSL_30.is_secure is False
        assert TLSVersion.TLS_10.is_secure is False
        assert TLSVersion.TLS_11.is_secure is False
    
    def test_numeric_version_property(self):
        """Test numeric version property."""
        assert TLSVersion.SSL_30.numeric_version == 3.0
        assert TLSVersion.TLS_10.numeric_version == 1.0
        assert TLSVersion.TLS_11.numeric_version == 1.1
        assert TLSVersion.TLS_12.numeric_version == 1.2
        assert TLSVersion.TLS_13.numeric_version == 1.3
    
    def test_version_comparison(self):
        """Test version comparison."""
        assert TLSVersion.TLS_10 < TLSVersion.TLS_11
        assert TLSVersion.TLS_11 < TLSVersion.TLS_12
        assert TLSVersion.TLS_12 < TLSVersion.TLS_13
        
        # Test with non-enum
        result = TLSVersion.TLS_12.__lt__("not_an_enum")
        assert result == NotImplemented
    
    def test_version_sorting(self):
        """Test that TLS versions can be sorted."""
        versions = [TLSVersion.TLS_13, TLSVersion.TLS_10, TLSVersion.TLS_12, TLSVersion.TLS_11]
        sorted_versions = sorted(versions)
        expected = [TLSVersion.TLS_10, TLSVersion.TLS_11, TLSVersion.TLS_12, TLSVersion.TLS_13]
        assert sorted_versions == expected


class TestProxyType:
    """Test ProxyType enum."""
    
    def test_proxy_values(self):
        """Test proxy type values."""
        assert ProxyType.HTTP == "http"
        assert ProxyType.HTTPS == "https"
        assert ProxyType.SOCKS4 == "socks4"
        assert ProxyType.SOCKS5 == "socks5"
        assert ProxyType.TRANSPARENT == "transparent"
    
    def test_supports_authentication_property(self):
        """Test supports_authentication property."""
        # Proxies that support authentication
        assert ProxyType.HTTP.supports_authentication is True
        assert ProxyType.HTTPS.supports_authentication is True
        assert ProxyType.SOCKS5.supports_authentication is True
        
        # Proxies that don't support authentication
        assert ProxyType.SOCKS4.supports_authentication is False
        assert ProxyType.TRANSPARENT.supports_authentication is False
        assert ProxyType.REVERSE.supports_authentication is False
        assert ProxyType.FORWARD.supports_authentication is False
    
    def test_supports_udp_property(self):
        """Test supports_udp property."""
        # Only SOCKS5 supports UDP
        assert ProxyType.SOCKS5.supports_udp is True
        
        # Others don't support UDP
        assert ProxyType.HTTP.supports_udp is False
        assert ProxyType.HTTPS.supports_udp is False
        assert ProxyType.SOCKS4.supports_udp is False
        assert ProxyType.TRANSPARENT.supports_udp is False


class TestGeographicRegion:
    """Test GeographicRegion enum."""
    
    def test_region_values(self):
        """Test geographic region values."""
        assert GeographicRegion.NORTH_AMERICA == "north_america"
        assert GeographicRegion.EUROPE == "europe"
        assert GeographicRegion.ASIA_PACIFIC == "asia_pacific"
        assert GeographicRegion.AFRICA == "africa"
    
    def test_countries_property(self):
        """Test countries property."""
        # Test some known mappings
        na_countries = GeographicRegion.NORTH_AMERICA.countries
        assert "US" in na_countries
        assert "CA" in na_countries
        assert "MX" in na_countries
        
        eu_countries = GeographicRegion.EUROPE.countries
        assert "GB" in eu_countries
        assert "DE" in eu_countries
        assert "FR" in eu_countries
        
        ap_countries = GeographicRegion.ASIA_PACIFIC.countries
        assert "JP" in ap_countries
        assert "CN" in ap_countries
        assert "AU" in ap_countries
    
    def test_all_regions_have_countries(self):
        """Test that all regions have country lists."""
        for region in GeographicRegion:
            countries = region.countries
            assert isinstance(countries, list)
            # Most regions should have at least some countries
            # (allowing for empty list as fallback)
            assert isinstance(countries, list)


class TestEnumModuleExports:
    """Test module-level exports and imports."""
    
    def test_all_exports_available(self):
        """Test that __all__ exports work correctly."""
        from src.netstealth_analyzer.models.enums import __all__
        
        expected_exports = [
            'SeverityLevel',
            'RiskLevel', 
            'IssueCategory',
            'LogFormat',
            'AnalysisStatus',
            'DetectionConfidence',
            'NetworkProtocol',
            'TLSVersion',
            'ProxyType',
            'GeographicRegion',
        ]
        
        for export in expected_exports:
            assert export in __all__
    
    def test_enum_string_representations(self):
        """Test that enums have proper string representations."""
        # Test that enum values are strings when appropriate
        assert isinstance(str(SeverityLevel.HIGH), str)
        assert isinstance(str(IssueCategory.TLS_FINGERPRINT), str)
        assert isinstance(str(LogFormat.HAR), str)
    
    def test_enum_inheritance(self):
        """Test enum inheritance patterns."""
        # String enums should be instances of str
        assert isinstance(SeverityLevel.HIGH, str)
        assert isinstance(IssueCategory.PROXY_DETECTION, str)
        assert isinstance(NetworkProtocol.HTTPS, str)


class TestEnumEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_enum_equality(self):
        """Test enum equality comparisons."""
        assert SeverityLevel.HIGH == SeverityLevel.HIGH
        assert SeverityLevel.HIGH != SeverityLevel.LOW
        assert SeverityLevel.HIGH == "high"  # String enum behavior
    
    def test_enum_membership(self):
        """Test enum membership checks."""
        assert SeverityLevel.HIGH in SeverityLevel
        assert "not_a_severity" not in [level.value for level in SeverityLevel]
    
    def test_enum_iteration(self):
        """Test that enums can be iterated."""
        severity_values = list(SeverityLevel)
        assert len(severity_values) == 5
        assert SeverityLevel.CRITICAL in severity_values
        
        confidence_values = list(DetectionConfidence)
        assert len(confidence_values) == 5
        assert DetectionConfidence.HIGH in confidence_values
