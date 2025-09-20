"""
Integration test for high-risk session verification.

Tests the complete analysis workflow with the high-risk sample file
to ensure all security issues are detected correctly.
"""

import pytest
import asyncio
from pathlib import Path


class TestHighRiskVerificationIntegration:
    """Integration tests for high-risk session verification."""
    
    @pytest.mark.asyncio
    async def test_high_risk_session_analysis(self):
        """Test complete analysis of high-risk session."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Build analyzer with all detectors
        builder = NetStealthAnalyzer.create()
        builder = builder.with_log("examples/sample_data/sample_high_risk_session.har")
        builder = builder.for_service("example.com")
        analyzer = builder.build()
        
        # Verify analyzer setup
        assert len(analyzer._detectors) >= 4, "Should have at least 4 detectors"
        assert len(analyzer._log_files) == 1, "Should have 1 log file"
        
        # Run analysis
        results = await analyzer.analyze()
        
        # Verify results structure
        assert results is not None
        assert hasattr(results, 'summary')
        assert hasattr(results, 'issues')
        assert hasattr(results.summary, 'overall_score')
        assert hasattr(results.summary, 'overall_risk_level')
    
    @pytest.mark.asyncio
    async def test_high_risk_score_validation(self):
        """Test that high-risk session produces expected score range."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        results = await analyzer.analyze()
        
        # Score should be in expected range for high-risk sessions
        assert 5 <= results.summary.overall_score <= 20, f"Score {results.summary.overall_score} outside expected range 5-20"
        
        # Risk level should be critical
        assert results.summary.overall_risk_level == "critical", f"Risk level should be critical, got {results.summary.overall_risk_level}"
    
    @pytest.mark.asyncio
    async def test_high_risk_issue_detection(self):
        """Test that high-risk session detects expected number of issues."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        results = await analyzer.analyze()
        
        # Should detect significant number of issues
        assert len(results.issues) >= 15, f"Expected at least 15 issues, found {len(results.issues)}"
        
        # Count issues by severity
        critical_count = len([i for i in results.issues if str(i.severity).lower() == "critical"])
        high_count = len([i for i in results.issues if str(i.severity).lower() == "high"])
        medium_count = len([i for i in results.issues if str(i.severity).lower() == "medium"])
        
        # Should have significant critical issues
        assert critical_count >= 5, f"Expected at least 5 critical issues, found {critical_count}"
        
        # Should have good distribution of severity levels
        assert high_count >= 3, f"Expected at least 3 high issues, found {high_count}"
        assert medium_count >= 1, f"Expected at least 1 medium issue, found {medium_count}"
    
    @pytest.mark.asyncio
    async def test_high_risk_security_categories(self):
        """Test that high-risk session detects multiple security categories."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        results = await analyzer.analyze()
        
        # Get unique categories
        categories_found = set(str(issue.category) for issue in results.issues)
        
        # Should detect multiple security categories
        assert len(categories_found) >= 5, f"Expected at least 5 security categories, found {len(categories_found)}"
        
        # Check for expected high-risk categories
        expected_categories = {
            "browser_automation", "proxy_detection", "ip_exposure", 
            "data_exposure", "fingerprinting", "tracking", "debug_leakage"
        }
        
        found_expected = categories_found.intersection(expected_categories)
        assert len(found_expected) >= 4, f"Expected at least 4 high-risk categories, found {len(found_expected)}: {found_expected}"
    
    @pytest.mark.asyncio
    async def test_detector_integration(self):
        """Test that all detectors are properly integrated and working."""
        from netstealth_analyzer import NetStealthAnalyzer
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        # Verify all expected detectors are loaded
        detector_names = [type(d).__name__ for d in analyzer._detectors]
        
        expected_detectors = ["TlsDetector", "BrowserDetector", "NetworkDetector", "ProxyDetector"]
        for expected in expected_detectors:
            assert expected in detector_names, f"Expected detector {expected} not found in {detector_names}"
        
        # Run analysis and verify each detector contributed
        results = await analyzer.analyze()
        
        # Should have issues from multiple detectors
        assert len(results.issues) > 0, "No issues detected - detectors may not be working"
        
        # Verify we have network traces
        assert len(results.network_traces) > 0, "No network traces found - parsing may not be working"
    
    @pytest.mark.asyncio
    async def test_analysis_performance(self):
        """Test that analysis completes within reasonable time."""
        from netstealth_analyzer import NetStealthAnalyzer
        import time
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        # Measure analysis time
        start_time = time.time()
        results = await analyzer.analyze()
        end_time = time.time()
        
        analysis_time = end_time - start_time
        
        # Should complete within reasonable time (adjust as needed)
        assert analysis_time < 30.0, f"Analysis took too long: {analysis_time:.2f} seconds"
        
        # Verify results are complete
        assert results is not None
        assert len(results.issues) > 0
        assert results.summary.overall_score >= 0
    
    @pytest.mark.asyncio
    async def test_result_serialization(self):
        """Test that analysis results can be properly serialized."""
        from netstealth_analyzer import NetStealthAnalyzer
        import json
        
        builder = NetStealthAnalyzer.create()
        analyzer = (builder
                   .with_log("examples/sample_data/sample_high_risk_session.har")
                   .for_service("example.com")
                   .build())
        
        results = await analyzer.analyze()
        
        # Test dictionary conversion
        result_dict = results.to_dict()
        assert isinstance(result_dict, dict)
        assert 'summary' in result_dict
        assert 'issues' in result_dict
        
        # Test JSON serialization
        json_str = json.dumps(result_dict, default=str)
        assert isinstance(json_str, str)
        assert len(json_str) > 0
        
        # Test summary dictionary
        summary_dict = results.to_summary_dict()
        assert isinstance(summary_dict, dict)
        assert 'result_id' in summary_dict
        assert 'issues_count' in summary_dict
