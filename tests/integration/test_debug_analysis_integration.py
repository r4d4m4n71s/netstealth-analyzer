"""
Integration test for debug analysis workflow.

Tests the step-by-step analysis pipeline to ensure each component
works correctly in isolation and integration.
"""

import pytest
import asyncio
from pathlib import Path


class TestDebugAnalysisIntegration:
    """Integration tests for debug analysis workflow."""
    
    def test_core_imports_integration(self):
        """Test that all core imports work in integration context."""
        # Test main analyzer import
        from netstealth_analyzer import NetStealthAnalyzer
        assert NetStealthAnalyzer is not None
        
        # Test result models
        from netstealth_analyzer.models.results import AnalysisSummary, AnalysisResult, ExecutionContext
        assert all([AnalysisSummary, AnalysisResult, ExecutionContext])
        
        # Test detector base
        from netstealth_analyzer.detectors.base import DetectionContext
        assert DetectionContext is not None
        
        # Test enums
        from netstealth_analyzer.models.enums import AnalysisStatus
        assert AnalysisStatus is not None
    
    def test_builder_creation_integration(self):
        """Test that builder creation works correctly."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Test builder creation
        builder = NetStealthAnalyzer.create()
        assert builder is not None
        assert hasattr(builder, 'with_log')
        assert hasattr(builder, 'with_detectors')
        assert hasattr(builder, 'build')
        
        # Test builder configuration
        builder = builder.with_log("examples/sample_data/sample_high_risk_session.har")
        assert len(builder._log_files) == 1
        
        # Test analyzer building
        analyzer = builder.build()
        assert analyzer is not None
        assert hasattr(analyzer, 'analyze')
        assert hasattr(analyzer, '_direct_analysis')
    
    def test_analyzer_components_integration(self):
        """Test that analyzer components are properly initialized."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .build())
        
        # Test analyzer attributes
        assert hasattr(analyzer, '_log_files')
        assert hasattr(analyzer, '_log_formats')
        assert hasattr(analyzer, '_parsers')
        assert hasattr(analyzer, '_detectors')
        
        # Test counts
        assert len(analyzer._log_files) == 1
        assert len(analyzer._log_formats) >= 1
        assert len(analyzer._parsers) >= 1
        assert len(analyzer._detectors) >= 1
        
        # Test file paths
        log_file = analyzer._log_files[0]
        assert isinstance(log_file, Path)
        assert log_file.name == "sample_high_risk_session.har"
    
    def test_execution_context_creation_integration(self):
        """Test ExecutionContext creation in integration context."""
        from netstealth_analyzer import NetStealthAnalyzer
        from netstealth_analyzer.models.results import ExecutionContext
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .build())
        
        # Test ExecutionContext creation
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=analyzer._log_files,
            input_formats=list(analyzer._log_formats.values())
        )
        
        assert execution_context is not None
        assert execution_context.analyzer_version == "2.0.0"
        assert len(execution_context.input_files) == 1
        assert len(execution_context.input_formats) >= 1
        assert execution_context.execution_id is not None
    
    @pytest.mark.asyncio
    async def test_direct_analysis_integration(self):
        """Test direct analysis method works correctly."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        # Test direct analysis call
        result = await analyzer._direct_analysis()
        
        # Verify result structure
        assert result is not None
        assert hasattr(result, 'summary')
        assert hasattr(result, 'issues')
        assert hasattr(result, 'network_traces')
        
        # Verify result content
        assert result.summary is not None
        assert isinstance(result.issues, list)
        assert isinstance(result.network_traces, list)
        
        # Verify analysis produced results
        assert result.summary.overall_score >= 0
        assert result.summary.overall_score <= 100
    
    @pytest.mark.asyncio
    async def test_step_by_step_analysis_integration(self):
        """Test each step of analysis pipeline individually."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Step 1: Create analyzer
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        # Step 2: Verify components
        assert len(analyzer._detectors) >= 1, "Should have at least 1 detector"
        assert len(analyzer._parsers) >= 1, "Should have at least 1 parser"
        assert len(analyzer._log_files) == 1, "Should have 1 log file"
        
        # Step 3: Run analysis
        result = await analyzer.analyze()
        
        # Step 4: Verify results
        assert result is not None, "Analysis should return results"
        assert len(result.issues) >= 0, "Should have issues list (may be empty)"
        assert result.summary.overall_score >= 0, "Should have valid score"
        
        # Step 5: Verify result completeness
        assert hasattr(result.summary, 'status'), "Should have analysis status"
        assert hasattr(result.summary, 'overall_risk_level'), "Should have risk level"
        assert hasattr(result, 'execution_context'), "Should have execution context"
    
    @pytest.mark.asyncio
    async def test_error_handling_integration(self):
        """Test error handling in analysis pipeline."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Test with non-existent file (should handle gracefully)
        builder = NetStealthAnalyzer.create()
        
        # This should raise an error during building
        with pytest.raises(Exception):
            analyzer = (builder
                       .with_log("non_existent_file.har")
                       .build())
    
    @pytest.mark.asyncio
    async def test_minimal_analysis_integration(self):
        """Test minimal analysis configuration validation."""
        from netstealth_analyzer import NetStealthAnalyzer
        from netstealth_analyzer.core.errors import ConfigurationError
        
        # Create minimal analyzer
        builder = NetStealthAnalyzer.create()
        
        # Building without log files should raise validation error
        with pytest.raises(ConfigurationError, match="No log files specified"):
            analyzer = builder.build()
        
        # Test with minimal valid configuration
        builder_with_log = NetStealthAnalyzer.create()
        analyzer = (builder_with_log
                   .with_log("examples/sample_data/sample_session.har")
                   .build())
        
        # Should be able to analyze
        result = await analyzer.analyze()
        
        assert result is not None
        assert hasattr(result, 'summary')
        assert hasattr(result, 'issues')
        assert isinstance(result.issues, list)
        assert isinstance(result.network_traces, list)
    
    @pytest.mark.asyncio
    async def test_detector_specific_integration(self):
        """Test that specific detectors can be configured and work."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Test with specific detector
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .build())
        
        # Verify detectors are loaded
        detector_names = [type(d).__name__ for d in analyzer._detectors]
        assert len(detector_names) >= 1, "Should have at least one detector"
        
        # Run analysis
        result = await analyzer.analyze()
        
        # Should produce some results with real data
        assert result is not None
        # Note: May or may not have issues depending on sample data and detectors
    
    def test_component_isolation_integration(self):
        """Test that components can be tested in isolation."""
        from netstealth_analyzer.models.results import ExecutionContext, AnalysisSummary
        from netstealth_analyzer.models.enums import AnalysisStatus
        from datetime import datetime, timezone
        
        # Test ExecutionContext in isolation
        context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=[Path("test.har")]
        )
        assert context.analyzer_version == "2.0.0"
        assert len(context.input_files) == 1
        
        # Test AnalysisSummary in isolation
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85
        )
        assert summary.status == AnalysisStatus.SUCCESS
        assert summary.overall_score == 85
        
        # Test computed properties
        assert summary.total_issues_count == 0  # No issues added yet
        assert summary.high_priority_issues_count == 0
