"""
Integration test for Python 3.13 compatibility.

Tests all major components to ensure they work correctly
with Python 3.13 and Pydantic v2 in an integration context.
"""

import pytest
import sys
from pathlib import Path


class TestPython313CompatibilityIntegration:
    """Integration tests for Python 3.13 compatibility."""
    
    def test_python_version_requirement(self):
        """Test Python version compatibility."""
        assert sys.version_info.major == 3
        assert sys.version_info.minor >= 13, "Python 3.13+ required"
    
    def test_core_module_imports(self):
        """Test core module imports work in integration context."""
        # Test main analyzer import
        from netstealth_analyzer import NetStealthAnalyzer
        assert NetStealthAnalyzer is not None
        
        # Test config import
        from netstealth_analyzer.config import NetStealthConfig
        assert NetStealthConfig is not None
        
        # Test compatibility module
        from netstealth_analyzer.compatibility import get_python_version, has_feature
        assert callable(get_python_version)
        assert callable(has_feature)
        
        # Test builder
        from netstealth_analyzer.builder import AnalyzerBuilder
        assert AnalyzerBuilder is not None
        
        # Test core components
        from netstealth_analyzer.core.events import EventBus
        from netstealth_analyzer.core.interfaces import ILogParser
        from netstealth_analyzer.core.errors import ParseError, ValidationError
        
        assert EventBus is not None
        assert ILogParser is not None
        assert ParseError is not None
        assert ValidationError is not None
    
    def test_pydantic_v2_model_imports(self):
        """Test Pydantic v2 model imports work correctly."""
        # Test network models
        from netstealth_analyzer.models.network import NetworkTrace, TLSInfo, ConnectionInfo, ProxyInfo
        assert all([NetworkTrace, TLSInfo, ConnectionInfo, ProxyInfo])
        
        # Test issue models
        from netstealth_analyzer.models.issues import Issue, DetectionRule, IssueEvidence, RemediationSuggestion
        assert all([Issue, DetectionRule, IssueEvidence, RemediationSuggestion])
        
        # Test result models
        from netstealth_analyzer.models.results import AnalysisResult, ProcessingStats, PerformanceMetrics
        assert all([AnalysisResult, ProcessingStats, PerformanceMetrics])
        
        # Test enum models
        from netstealth_analyzer.models.enums import SeverityLevel, IssueCategory, LogFormat
        assert all([SeverityLevel, IssueCategory, LogFormat])
    
    def test_parser_module_imports(self):
        """Test parser module imports work correctly."""
        # Test base parser
        from netstealth_analyzer.parsers.base import ILogParser, BaseLogParser, ParseResult
        assert all([ILogParser, BaseLogParser, ParseResult])
        
        # Test HAR parser (required)
        from netstealth_analyzer.parsers.har import HarParser
        assert HarParser is not None
        
        # Test other parsers (may be optional)
        try:
            from netstealth_analyzer.parsers.mitmproxy import MitmproxyParser
            from netstealth_analyzer.parsers.browser import BrowserLogParser
            from netstealth_analyzer.parsers.poc import PocExecutionParser
        except ImportError:
            # Some parsers may be optional
            pass
    
    def test_pydantic_v2_features_integration(self):
        """Test Pydantic v2 features work in integration context."""
        from netstealth_analyzer.models.network import NetworkTrace
        from netstealth_analyzer.models.enums import NetworkProtocol
        from datetime import datetime, timezone
        
        # Test creating a model instance
        trace = NetworkTrace(
            trace_id="test_trace",
            protocol=NetworkProtocol.HTTP,
            trace_start=datetime.now(timezone.utc)
        )
        
        # Test computed fields
        assert hasattr(trace, 'total_hops')
        assert hasattr(trace, 'average_risk_score')
        
        # Test model serialization
        data = trace.model_dump()
        assert isinstance(data, dict)
        assert 'trace_id' in data
        assert 'protocol' in data
        assert 'trace_start' in data
        assert 'total_hops' in data
        assert 'average_risk_score' in data
    
    def test_python313_specific_features(self):
        """Test Python 3.13 specific features are available."""
        # Test built-in tomllib
        import tomllib
        assert tomllib is not None
        
        # Test TaskGroup availability
        import asyncio
        assert hasattr(asyncio, 'TaskGroup')
        
        # Test @override decorator availability
        from netstealth_analyzer.compatibility import override
        assert override is not None
    
    @pytest.mark.asyncio
    async def test_full_integration_workflow(self):
        """Test complete workflow works with Python 3.13."""
        from netstealth_analyzer import NetStealthAnalyzer
        from pathlib import Path
        
        # Create analyzer using builder pattern
        builder = NetStealthAnalyzer.create()
        
        # Test that builder works
        assert builder is not None
        assert hasattr(builder, 'build')
        
        # Add a sample HAR file for validation (use existing sample)
        sample_har = Path("examples/sample_data/sample_session.har")
        if sample_har.exists():
            builder.with_log(sample_har)
            
            # Test building analyzer
            analyzer = builder.build()
            assert analyzer is not None
            assert hasattr(analyzer, 'analyze')
        else:
            # If no sample file, test that builder validation works correctly
            from netstealth_analyzer.core.errors import ConfigurationError
            with pytest.raises(ConfigurationError, match="No log files specified"):
                builder.build()
