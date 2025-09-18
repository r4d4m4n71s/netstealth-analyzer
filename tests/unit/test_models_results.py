"""
Unit tests for NetStealth Analyzer result models.

Tests the ProcessingStats, PerformanceMetrics, ExecutionContext, 
AnalysisSummary, and AnalysisResult models with comprehensive
coverage of validation, computation, and business logic.
"""

import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import UUID
from typing import Dict, Any, List
import asyncio

from src.netstealth_analyzer.models.results import (
    ProcessingStats,
    PerformanceMetrics,
    ExecutionContext,
    AnalysisSummary,
    AnalysisResult
)
from src.netstealth_analyzer.models.enums import (
    AnalysisStatus,
    SeverityLevel,
    IssueCategory,
    LogFormat
)
from src.netstealth_analyzer.models.issues import Issue
from src.netstealth_analyzer.models.network import NetworkTrace


class TestProcessingStats:
    """Test ProcessingStats model."""
    
    def test_stats_creation_defaults(self):
        """Test creating stats with default values."""
        stats = ProcessingStats()
        
        assert stats.files_processed == 0
        assert stats.files_failed == 0
        assert stats.total_file_size_mb == 0.0
        assert stats.log_entries_parsed == 0
        assert stats.log_entries_skipped == 0
        assert stats.parse_errors == 0
        assert stats.detectors_executed == 0
        assert stats.detection_rules_applied == 0
        assert stats.issues_detected == 0
        assert stats.false_positives_filtered == 0
        assert stats.processing_time_ms == 0.0
        assert stats.parsing_time_ms == 0.0
        assert stats.detection_time_ms == 0.0
        assert stats.reporting_time_ms == 0.0
        assert stats.peak_memory_mb == 0.0
        assert stats.average_memory_mb == 0.0
    
    def test_stats_creation_with_values(self):
        """Test creating stats with specific values."""
        stats = ProcessingStats(
            files_processed=10,
            files_failed=2,
            total_file_size_mb=150.5,
            log_entries_parsed=5000,
            log_entries_skipped=100,
            parse_errors=5,
            detectors_executed=8,
            detection_rules_applied=25,
            issues_detected=15,
            false_positives_filtered=3,
            processing_time_ms=30000.0,
            parsing_time_ms=15000.0,
            detection_time_ms=10000.0,
            reporting_time_ms=5000.0,
            peak_memory_mb=512.0,
            average_memory_mb=256.0
        )
        
        assert stats.files_processed == 10
        assert stats.files_failed == 2
        assert stats.total_file_size_mb == 150.5
        assert stats.log_entries_parsed == 5000
        assert stats.log_entries_skipped == 100
        assert stats.parse_errors == 5
        assert stats.detectors_executed == 8
        assert stats.detection_rules_applied == 25
        assert stats.issues_detected == 15
        assert stats.false_positives_filtered == 3
        assert stats.processing_time_ms == 30000.0
        assert stats.parsing_time_ms == 15000.0
        assert stats.detection_time_ms == 10000.0
        assert stats.reporting_time_ms == 5000.0
        assert stats.peak_memory_mb == 512.0
        assert stats.average_memory_mb == 256.0
    
    def test_validation_non_negative(self):
        """Test validation of non-negative fields."""
        # Valid values
        stats = ProcessingStats(files_processed=0, files_failed=0)
        assert stats.files_processed == 0
        
        # Invalid negative values
        with pytest.raises(ValueError):
            ProcessingStats(files_processed=-1)
        
        with pytest.raises(ValueError):
            ProcessingStats(total_file_size_mb=-1.0)
        
        with pytest.raises(ValueError):
            ProcessingStats(processing_time_ms=-1.0)
    
    def test_success_rate_computation(self):
        """Test success rate computed property."""
        # No files processed
        stats = ProcessingStats()
        assert stats.success_rate == 1.0
        
        # All files successful
        stats = ProcessingStats(files_processed=10, files_failed=0)
        assert stats.success_rate == 1.0
        
        # Some failures
        stats = ProcessingStats(files_processed=8, files_failed=2)
        assert stats.success_rate == 0.8
        
        # All failures
        stats = ProcessingStats(files_processed=0, files_failed=5)
        assert stats.success_rate == 0.0
    
    def test_parse_success_rate_computation(self):
        """Test parse success rate computed property."""
        # No entries
        stats = ProcessingStats()
        assert stats.parse_success_rate == 1.0
        
        # All successful
        stats = ProcessingStats(log_entries_parsed=1000, log_entries_skipped=0, parse_errors=0)
        assert stats.parse_success_rate == 1.0
        
        # Some failures
        stats = ProcessingStats(log_entries_parsed=800, log_entries_skipped=100, parse_errors=100)
        assert stats.parse_success_rate == 0.8
        
        # All failures
        stats = ProcessingStats(log_entries_parsed=0, log_entries_skipped=500, parse_errors=500)
        assert stats.parse_success_rate == 0.0
    
    def test_processing_speed_computation(self):
        """Test processing speed computed property."""
        # No processing time
        stats = ProcessingStats()
        assert stats.processing_speed_entries_per_second == 0.0
        
        # Normal processing
        stats = ProcessingStats(log_entries_parsed=1000, processing_time_ms=10000.0)
        assert stats.processing_speed_entries_per_second == 100.0
        
        # Fast processing
        stats = ProcessingStats(log_entries_parsed=5000, processing_time_ms=1000.0)
        assert stats.processing_speed_entries_per_second == 5000.0
    
    def test_get_performance_summary(self):
        """Test performance summary generation."""
        stats = ProcessingStats(
            files_processed=8,
            files_failed=2,
            log_entries_parsed=1000,
            log_entries_skipped=50,
            parse_errors=10,
            processing_time_ms=20000.0,
            peak_memory_mb=256.0,
            issues_detected=5
        )
        
        summary = stats.get_performance_summary()
        
        assert isinstance(summary, dict)
        assert summary['success_rate'] == 0.8
        assert summary['parse_success_rate'] == 1000 / 1060  # 1000 / (1000 + 50 + 10)
        assert summary['processing_speed'] == 50.0  # 1000 / 20000 * 1000
        assert summary['total_time_seconds'] == 20.0
        assert summary['peak_memory_mb'] == 256.0
        assert summary['files_processed'] == 8
        assert summary['issues_detected'] == 5


class TestPerformanceMetrics:
    """Test PerformanceMetrics model."""
    
    def test_metrics_creation_defaults(self):
        """Test creating metrics with default values."""
        metrics = PerformanceMetrics()
        
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.timeout_requests == 0
        assert metrics.average_response_time_ms == 0.0
        assert metrics.median_response_time_ms == 0.0
        assert metrics.min_response_time_ms == 0.0
        assert metrics.max_response_time_ms == 0.0
        assert metrics.p95_response_time_ms == 0.0
        assert metrics.p99_response_time_ms == 0.0
        assert metrics.requests_per_second == 0.0
        assert metrics.bytes_per_second == 0.0
        assert metrics.error_rate_percent == 0.0
        assert metrics.timeout_rate_percent == 0.0
        assert metrics.connection_time_ms == 0.0
        assert metrics.ssl_handshake_time_ms == 0.0
        assert metrics.dns_lookup_time_ms == 0.0
        assert metrics.total_bytes_sent == 0
        assert metrics.total_bytes_received == 0
        assert metrics.compression_ratio == 1.0
    
    def test_metrics_creation_with_values(self):
        """Test creating metrics with specific values."""
        metrics = PerformanceMetrics(
            total_requests=1000,
            successful_requests=950,
            failed_requests=30,
            timeout_requests=20,
            average_response_time_ms=250.0,
            median_response_time_ms=200.0,
            min_response_time_ms=50.0,
            max_response_time_ms=2000.0,
            p95_response_time_ms=800.0,
            p99_response_time_ms=1500.0,
            requests_per_second=100.0,
            bytes_per_second=1048576.0,
            error_rate_percent=3.0,
            timeout_rate_percent=2.0,
            connection_time_ms=50.0,
            ssl_handshake_time_ms=100.0,
            dns_lookup_time_ms=25.0,
            total_bytes_sent=5242880,
            total_bytes_received=10485760,
            compression_ratio=0.8
        )
        
        assert metrics.total_requests == 1000
        assert metrics.successful_requests == 950
        assert metrics.failed_requests == 30
        assert metrics.timeout_requests == 20
        assert metrics.average_response_time_ms == 250.0
        assert metrics.median_response_time_ms == 200.0
        assert metrics.min_response_time_ms == 50.0
        assert metrics.max_response_time_ms == 2000.0
        assert metrics.p95_response_time_ms == 800.0
        assert metrics.p99_response_time_ms == 1500.0
        assert metrics.requests_per_second == 100.0
        assert metrics.bytes_per_second == 1048576.0
        assert metrics.error_rate_percent == 3.0
        assert metrics.timeout_rate_percent == 2.0
        assert metrics.connection_time_ms == 50.0
        assert metrics.ssl_handshake_time_ms == 100.0
        assert metrics.dns_lookup_time_ms == 25.0
        assert metrics.total_bytes_sent == 5242880
        assert metrics.total_bytes_received == 10485760
        assert metrics.compression_ratio == 0.8
    
    def test_validation_ranges(self):
        """Test validation of field ranges."""
        # Valid values
        metrics = PerformanceMetrics(error_rate_percent=50.0, timeout_rate_percent=25.0)
        assert metrics.error_rate_percent == 50.0
        assert metrics.timeout_rate_percent == 25.0
        
        # Invalid ranges
        with pytest.raises(ValueError):
            PerformanceMetrics(error_rate_percent=-1.0)
        
        with pytest.raises(ValueError):
            PerformanceMetrics(error_rate_percent=101.0)
        
        with pytest.raises(ValueError):
            PerformanceMetrics(timeout_rate_percent=150.0)
        
        with pytest.raises(ValueError):
            PerformanceMetrics(total_requests=-1)
    
    def test_success_rate_percent_computation(self):
        """Test success rate percentage computed property."""
        # No requests
        metrics = PerformanceMetrics()
        assert metrics.success_rate_percent == 100.0
        
        # All successful
        metrics = PerformanceMetrics(total_requests=100, successful_requests=100)
        assert metrics.success_rate_percent == 100.0
        
        # Some failures
        metrics = PerformanceMetrics(total_requests=100, successful_requests=85)
        assert metrics.success_rate_percent == 85.0
        
        # All failures
        metrics = PerformanceMetrics(total_requests=100, successful_requests=0)
        assert metrics.success_rate_percent == 0.0
    
    def test_total_bytes_transferred_computation(self):
        """Test total bytes transferred computed property."""
        metrics = PerformanceMetrics(total_bytes_sent=1000, total_bytes_received=2000)
        assert metrics.total_bytes_transferred == 3000
    
    def test_average_request_size_computation(self):
        """Test average request size computed property."""
        # No requests
        metrics = PerformanceMetrics()
        assert metrics.average_request_size_bytes == 0.0
        
        # Normal case
        metrics = PerformanceMetrics(total_requests=10, total_bytes_sent=1000)
        assert metrics.average_request_size_bytes == 100.0
    
    def test_average_response_size_computation(self):
        """Test average response size computed property."""
        # No successful requests
        metrics = PerformanceMetrics()
        assert metrics.average_response_size_bytes == 0.0
        
        # Normal case
        metrics = PerformanceMetrics(successful_requests=5, total_bytes_received=2500)
        assert metrics.average_response_size_bytes == 500.0
    
    def test_get_quality_assessment(self):
        """Test quality assessment generation."""
        # Excellent performance
        metrics = PerformanceMetrics(
            average_response_time_ms=50.0,
            total_requests=1000,
            successful_requests=995,
            error_rate_percent=0.5
        )
        
        assessment = metrics.get_quality_assessment()
        
        assert assessment['response_time'] == 'excellent'
        assert assessment['reliability'] == 'excellent'
        assert assessment['error_rate'] == 'excellent'
        
        # Poor performance
        metrics = PerformanceMetrics(
            average_response_time_ms=5000.0,
            total_requests=1000,
            successful_requests=800,
            error_rate_percent=15.0
        )
        
        assessment = metrics.get_quality_assessment()
        
        assert assessment['response_time'] == 'poor'
        assert assessment['reliability'] == 'poor'
        assert assessment['error_rate'] == 'poor'
        
        # Mixed performance
        metrics = PerformanceMetrics(
            average_response_time_ms=300.0,  # good
            total_requests=1000,
            successful_requests=960,  # good
            error_rate_percent=3.0  # good
        )
        
        assessment = metrics.get_quality_assessment()
        
        assert assessment['response_time'] == 'good'
        assert assessment['reliability'] == 'good'
        assert assessment['error_rate'] == 'good'


class TestExecutionContext:
    """Test ExecutionContext model."""
    
    def test_context_creation_defaults(self):
        """Test creating context with default values."""
        context = ExecutionContext()
        
        assert UUID(context.execution_id)  # Should be valid UUID
        assert context.session_id is None
        assert context.correlation_id is None
        assert isinstance(context.start_time, datetime)
        assert context.end_time is None
        assert context.analyzer_version == "2.0.0"
        assert context.python_version == ""
        assert context.platform == ""
        assert context.hostname == ""
        assert context.configuration_hash is None
        assert context.configuration_summary == {}
        assert context.input_files == []
        assert context.input_formats == []
        assert context.components_used == []
        assert context.plugins_loaded == []
        assert context.max_memory_usage_mb == 0.0
        assert context.cpu_time_seconds == 0.0
    
    def test_context_creation_with_values(self):
        """Test creating context with specific values."""
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=30)
        
        context = ExecutionContext(
            session_id="session-123",
            correlation_id="corr-456",
            start_time=start_time,
            end_time=end_time,
            analyzer_version="2.1.0",
            python_version="3.13.7",
            platform="Windows-11",
            hostname="test-machine",
            configuration_hash="abc123",
            configuration_summary={"debug": True, "timeout": 30},
            input_files=[Path("test1.har"), Path("test2.log")],
            input_formats=[LogFormat.HAR, LogFormat.MITMPROXY],
            components_used=["parser", "detector", "reporter"],
            plugins_loaded=["plugin1", "plugin2"],
            max_memory_usage_mb=512.0,
            cpu_time_seconds=25.5
        )
        
        assert context.session_id == "session-123"
        assert context.correlation_id == "corr-456"
        assert context.start_time == start_time
        assert context.end_time == end_time
        assert context.analyzer_version == "2.1.0"
        assert context.python_version == "3.13.7"
        assert context.platform == "Windows-11"
        assert context.hostname == "test-machine"
        assert context.configuration_hash == "abc123"
        assert context.configuration_summary == {"debug": True, "timeout": 30}
        assert context.input_files == [Path("test1.har"), Path("test2.log")]
        assert context.input_formats == [LogFormat.HAR, LogFormat.MITMPROXY]
        assert context.components_used == ["parser", "detector", "reporter"]
        assert context.plugins_loaded == ["plugin1", "plugin2"]
        assert context.max_memory_usage_mb == 512.0
        assert context.cpu_time_seconds == 25.5
    
    def test_input_files_validation(self):
        """Test input files validation and conversion."""
        # String paths should be converted to Path objects
        context = ExecutionContext(input_files=["test1.har", "test2.log"])
        assert all(isinstance(f, Path) for f in context.input_files)
        assert context.input_files == [Path("test1.har"), Path("test2.log")]
        
        # Path objects should remain Path objects
        paths = [Path("test1.har"), Path("test2.log")]
        context = ExecutionContext(input_files=paths)
        assert context.input_files == paths
    
    def test_validation_non_negative(self):
        """Test validation of non-negative fields."""
        # Valid values
        context = ExecutionContext(max_memory_usage_mb=0.0, cpu_time_seconds=0.0)
        assert context.max_memory_usage_mb == 0.0
        assert context.cpu_time_seconds == 0.0
        
        # Invalid negative values
        with pytest.raises(ValueError):
            ExecutionContext(max_memory_usage_mb=-1.0)
        
        with pytest.raises(ValueError):
            ExecutionContext(cpu_time_seconds=-1.0)
    
    def test_duration_seconds_computation(self):
        """Test duration seconds computed property."""
        start_time = datetime.now(timezone.utc)
        
        # No end time
        context = ExecutionContext(start_time=start_time)
        assert context.duration_seconds is None
        
        # With end time
        end_time = start_time + timedelta(seconds=30, microseconds=500000)
        context = ExecutionContext(start_time=start_time, end_time=end_time)
        assert abs(context.duration_seconds - 30.5) < 0.001
    
    def test_is_completed_property(self):
        """Test is_completed computed property."""
        # Not completed
        context = ExecutionContext()
        assert context.is_completed is False
        
        # Completed
        context = ExecutionContext(end_time=datetime.now(timezone.utc))
        assert context.is_completed is True
    
    def test_mark_completed(self):
        """Test mark_completed method."""
        context = ExecutionContext()
        assert context.end_time is None
        assert context.is_completed is False
        
        context.mark_completed()
        
        assert context.end_time is not None
        assert isinstance(context.end_time, datetime)
        assert context.is_completed is True
        
        # Should not update if already completed
        original_end_time = context.end_time
        context.mark_completed()
        assert context.end_time == original_end_time
    
    def test_get_execution_summary(self):
        """Test execution summary generation."""
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=45)
        
        context = ExecutionContext(
            start_time=start_time,
            end_time=end_time,
            analyzer_version="2.1.0",
            input_files=[Path("test1.har"), Path("test2.log")],
            components_used=["parser", "detector"],
            plugins_loaded=["plugin1"],
            max_memory_usage_mb=256.0
        )
        
        summary = context.get_execution_summary()
        
        assert isinstance(summary, dict)
        assert summary['execution_id'] == context.execution_id
        assert abs(summary['duration_seconds'] - 45.0) < 0.001
        assert summary['analyzer_version'] == "2.1.0"
        assert summary['input_files_count'] == 2
        assert summary['components_used'] == ["parser", "detector"]
        assert summary['plugins_loaded'] == ["plugin1"]
        assert summary['max_memory_mb'] == 256.0
        assert summary['completed'] is True


class TestAnalysisSummary:
    """Test AnalysisSummary model."""
    
    def test_summary_creation_minimal(self):
        """Test creating summary with minimal required data."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85
        )
        
        assert summary.status == AnalysisStatus.SUCCESS
        assert summary.overall_score == 85
        assert summary.critical_issues_count == 0
        assert summary.high_issues_count == 0
        assert summary.medium_issues_count == 0
        assert summary.low_issues_count == 0
        assert summary.info_issues_count == 0
        assert summary.issues_by_category == {}
        assert summary.proxy_chain_functional is False
        assert summary.oauth_success is False
        assert summary.antibot_bypass_success is False
        assert summary.geographic_masking_active is False
        assert summary.tls_security_adequate is False
        assert summary.overall_risk_level == "unknown"
        assert summary.risk_score == 0.0
        assert summary.analysis_duration_ms == 0.0
        assert summary.processing_efficiency == 0.0
        assert isinstance(summary.timestamp, datetime)
    
    def test_summary_creation_full(self):
        """Test creating summary with all data."""
        timestamp = datetime.now(timezone.utc)
        
        summary = AnalysisSummary(
            status=AnalysisStatus.PARTIAL_SUCCESS,
            overall_score=75,
            critical_issues_count=2,
            high_issues_count=5,
            medium_issues_count=8,
            low_issues_count=10,
            info_issues_count=3,
            issues_by_category={"auth": 5, "network": 3},
            proxy_chain_functional=True,
            oauth_success=True,
            antibot_bypass_success=False,
            geographic_masking_active=True,
            tls_security_adequate=True,
            overall_risk_level="medium",
            risk_score=0.6,
            analysis_duration_ms=45000.0,
            processing_efficiency=0.85,
            timestamp=timestamp
        )
        
        assert summary.status == AnalysisStatus.PARTIAL_SUCCESS
        assert summary.overall_score == 75
        assert summary.critical_issues_count == 2
        assert summary.high_issues_count == 5
        assert summary.medium_issues_count == 8
        assert summary.low_issues_count == 10
        assert summary.info_issues_count == 3
        assert summary.issues_by_category == {"auth": 5, "network": 3}
        assert summary.proxy_chain_functional is True
        assert summary.oauth_success is True
        assert summary.antibot_bypass_success is False
        assert summary.geographic_masking_active is True
        assert summary.tls_security_adequate is True
        assert summary.overall_risk_level == "medium"
        assert summary.risk_score == 0.6
        assert summary.analysis_duration_ms == 45000.0
        assert summary.processing_efficiency == 0.85
        assert summary.timestamp == timestamp
    
    def test_validation_score_range(self):
        """Test validation of score ranges."""
        # Valid scores
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=0)
        assert summary.overall_score == 0
        
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=100)
        assert summary.overall_score == 100
        
        # Invalid scores
        with pytest.raises(ValueError):
            AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=-1)
        
        with pytest.raises(ValueError):
            AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=101)
    
    def test_validation_non_negative_counts(self):
        """Test validation of non-negative count fields."""
        # Valid counts
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            critical_issues_count=0,
            analysis_duration_ms=0.0
        )
        assert summary.critical_issues_count == 0
        
        # Invalid negative counts
        with pytest.raises(ValueError):
            AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=85,
                critical_issues_count=-1
            )
        
        with pytest.raises(ValueError):
            AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=85,
                analysis_duration_ms=-1.0
            )
    
    def test_risk_level_validation(self):
        """Test risk level validation."""
        # Valid risk levels
        valid_levels = ['safe', 'low', 'medium', 'high', 'critical', 'unknown']
        for level in valid_levels:
            summary = AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=85,
                overall_risk_level=level
            )
            assert summary.overall_risk_level == level
        
        # Invalid risk level
        with pytest.raises(ValueError):
            AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=85,
                overall_risk_level="invalid"
            )
    
    def test_total_issues_count_computation(self):
        """Test total issues count computed property."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            critical_issues_count=2,
            high_issues_count=5,
            medium_issues_count=8,
            low_issues_count=10,
            info_issues_count=3
        )
        
        assert summary.total_issues_count == 28
    
    def test_high_priority_issues_count_computation(self):
        """Test high priority issues count computed property."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            critical_issues_count=2,
            high_issues_count=5,
            medium_issues_count=8
        )
        
        assert summary.high_priority_issues_count == 7
    
    def test_success_indicators_count_computation(self):
        """Test success indicators count computed property."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            proxy_chain_functional=True,
            oauth_success=True,
            antibot_bypass_success=False,
            geographic_masking_active=True,
            tls_security_adequate=False
        )
        
        assert summary.success_indicators_count == 3
    
    def test_update_from_issues(self):
        """Test updating summary from list of issues."""
        # Create test issues
        issues = [
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.CRITICAL,
                title="Critical auth issue",
                description="Test",
                confidence=0.9,
                impact_score=90
            ),
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="High auth issue",
                description="Test",
                confidence=0.8,
                impact_score=80
            ),
            Issue(
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.MEDIUM,
                title="Medium network issue",
                description="Test",
                confidence=0.7,
                impact_score=60
            ),
            Issue(
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.LOW,
                title="Low network issue",
                description="Test",
                confidence=0.6,
                impact_score=40
            ),
            Issue(
                category=IssueCategory.PRIVACY_VIOLATION,
                severity=SeverityLevel.INFO,
                title="Info privacy issue",
                description="Test",
                confidence=0.5,
                impact_score=20
            )
        ]
        
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=100)
        summary.update_from_issues(issues)
        
        # Check severity counts
        assert summary.critical_issues_count == 1
        assert summary.high_issues_count == 1
        assert summary.medium_issues_count == 1
        assert summary.low_issues_count == 1
        assert summary.info_issues_count == 1
        
        # Check category counts
        assert summary.issues_by_category['authentication'] == 2
        assert summary.issues_by_category['network_anomaly'] == 2
        assert summary.issues_by_category['privacy_violation'] == 1
        
        # Check that overall score was recalculated
        assert summary.overall_score < 100  # Should be reduced due to issues
    
    def test_calculate_overall_score(self):
        """Test overall score calculation."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=100,  # Will be recalculated
            critical_issues_count=1,  # -20 points
            high_issues_count=2,      # -20 points
            medium_issues_count=3,    # -15 points
            low_issues_count=5,       # -10 points
            info_issues_count=2       # -2 points
        )
        
        # Manually trigger score calculation
        summary._calculate_overall_score()
        
        # Expected: 100 - 20 - 20 - 15 - 10 - 2 = 33
        assert summary.overall_score == 33
        
        # Test with success indicators
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=100,
            critical_issues_count=1,  # -20 points
            proxy_chain_functional=True,  # +5 points
            oauth_success=True,           # +5 points
            tls_security_adequate=True    # +5 points
        )
        
        summary._calculate_overall_score()
        
        # Expected: 100 - 20 + 15 = 95
        assert summary.overall_score == 95
    
    def test_get_severity_distribution(self):
        """Test severity distribution calculation."""
        # No issues
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=100)
        distribution = summary.get_severity_distribution()
        
        for severity in SeverityLevel:
            assert distribution[severity.value] == 0.0
        
        # With issues
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            critical_issues_count=2,  # 20%
            high_issues_count=3,      # 30%
            medium_issues_count=5,    # 50%
            low_issues_count=0,       # 0%
            info_issues_count=0       # 0%
        )
        
        distribution = summary.get_severity_distribution()
        
        assert distribution[SeverityLevel.CRITICAL.value] == 20.0
        assert distribution[SeverityLevel.HIGH.value] == 30.0
        assert distribution[SeverityLevel.MEDIUM.value] == 50.0
        assert distribution[SeverityLevel.LOW.value] == 0.0
        assert distribution[SeverityLevel.INFO.value] == 0.0


class TestAnalysisResult:
    """Test AnalysisResult model."""
    
    def test_result_creation_minimal(self):
        """Test creating result with minimal required data."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        
        result = AnalysisResult(summary=summary, execution_context=context)
        
        assert UUID(result.result_id)  # Should be valid UUID
        assert result.summary == summary
        assert result.execution_context == context
        assert result.issues == []
        assert result.network_traces == []
        assert isinstance(result.performance_metrics, PerformanceMetrics)
        assert isinstance(result.processing_stats, ProcessingStats)
        assert result.session_timeline is None
        assert result.fingerprint_analysis is None
        assert result.remediation_plan is None
        assert result.raw_log_excerpts == {}
        assert result.debug_information == {}
    
    def test_result_creation_full(self):
        """Test creating result with all data."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        performance = PerformanceMetrics(total_requests=100, successful_requests=95)
        stats = ProcessingStats(files_processed=5, issues_detected=3)
        
        # Create test issues
        issue1 = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        issue2 = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            title="Network issue",
            description="Test",
            confidence=0.7,
            impact_score=60
        )
        
        # Create test network trace
        trace = NetworkTrace(
            trace_id="trace-123",
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            port=443
        )
        
        result = AnalysisResult(
            summary=summary,
            execution_context=context,
            issues=[issue1, issue2],
            network_traces=[trace],
            performance_metrics=performance,
            processing_stats=stats,
            session_timeline=[{"event": "start", "timestamp": "2023-01-01T00:00:00Z"}],
            fingerprint_analysis={"browser": "Chrome", "version": "120"},
            remediation_plan={"priority": "high", "steps": ["fix auth"]},
            raw_log_excerpts={"sample": "log data"},
            debug_information={"debug": True}
        )
        
        assert result.summary == summary
        assert result.execution_context == context
        assert len(result.issues) == 2
        assert result.issues[0] == issue1
        assert result.issues[1] == issue2
        assert len(result.network_traces) == 1
        assert result.network_traces[0] == trace
        assert result.performance_metrics == performance
        assert result.processing_stats == stats
        assert result.session_timeline == [{"event": "start", "timestamp": "2023-01-01T00:00:00Z"}]
        assert result.fingerprint_analysis == {"browser": "Chrome", "version": "120"}
        assert result.remediation_plan == {"priority": "high", "steps": ["fix auth"]}
        assert result.raw_log_excerpts == {"sample": "log data"}
        assert result.debug_information == {"debug": True}
    
    def test_add_issue(self):
        """Test adding issue to results."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=100)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        assert len(result.issues) == 0
        assert result.summary.total_issues_count == 0
        
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        result.add_issue(issue)
        
        assert len(result.issues) == 1
        assert result.issues[0] == issue
        # Summary should be updated
        assert result.summary.total_issues_count == 1
        assert result.summary.high_issues_count == 1
    
    def test_add_network_trace(self):
        """Test adding network trace to results."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        assert len(result.network_traces) == 0
        
        trace = NetworkTrace(
            trace_id="trace-123",
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            port=443
        )
        
        result.add_network_trace(trace)
        
        assert len(result.network_traces) == 1
        assert result.network_traces[0] == trace
    
    def test_get_issues_by_severity(self):
        """Test getting issues by severity level."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add issues with different severities
        critical_issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.CRITICAL,
            title="Critical issue",
            description="Test",
            confidence=0.9,
            impact_score=95
        )
        
        high_issue = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            title="High issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        medium_issue = Issue(
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.MEDIUM,
            title="Medium issue",
            description="Test",
            confidence=0.7,
            impact_score=60
        )
        
        result.add_issue(critical_issue)
        result.add_issue(high_issue)
        result.add_issue(medium_issue)
        
        # Test filtering by severity
        critical_issues = result.get_issues_by_severity(SeverityLevel.CRITICAL)
        assert len(critical_issues) == 1
        assert critical_issues[0] == critical_issue
        
        high_issues = result.get_issues_by_severity(SeverityLevel.HIGH)
        assert len(high_issues) == 1
        assert high_issues[0] == high_issue
        
        low_issues = result.get_issues_by_severity(SeverityLevel.LOW)
        assert len(low_issues) == 0
    
    def test_get_issues_by_category(self):
        """Test getting issues by category."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add issues with different categories
        auth_issue1 = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue 1",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        auth_issue2 = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.MEDIUM,
            title="Auth issue 2",
            description="Test",
            confidence=0.7,
            impact_score=60
        )
        
        network_issue = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            title="Network issue",
            description="Test",
            confidence=0.8,
            impact_score=75
        )
        
        result.add_issue(auth_issue1)
        result.add_issue(auth_issue2)
        result.add_issue(network_issue)
        
        # Test filtering by category
        auth_issues = result.get_issues_by_category(IssueCategory.AUTHENTICATION)
        assert len(auth_issues) == 2
        assert auth_issue1 in auth_issues
        assert auth_issue2 in auth_issues
        
        network_issues = result.get_issues_by_category(IssueCategory.NETWORK_ANOMALY)
        assert len(network_issues) == 1
        assert network_issues[0] == network_issue
        
        privacy_issues = result.get_issues_by_category(IssueCategory.PRIVACY_VIOLATION)
        assert len(privacy_issues) == 0
    
    def test_get_high_priority_issues(self):
        """Test getting high priority issues."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add issues with different severities
        critical_issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.CRITICAL,
            title="Critical issue",
            description="Test",
            confidence=0.9,
            impact_score=95
        )
        
        high_issue = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            title="High issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        medium_issue = Issue(
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.MEDIUM,
            title="Medium issue",
            description="Test",
            confidence=0.7,
            impact_score=60
        )
        
        result.add_issue(critical_issue)
        result.add_issue(high_issue)
        result.add_issue(medium_issue)
        
        high_priority = result.get_high_priority_issues()
        assert len(high_priority) == 2
        assert critical_issue in high_priority
        assert high_issue in high_priority
        assert medium_issue not in high_priority
    
    def test_get_issues_with_remediation(self):
        """Test getting issues with remediation suggestions."""
        from src.netstealth_analyzer.models.issues import RemediationSuggestion
        
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Issue with remediation
        issue_with_remediation = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Issue with fix",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        
        remediation = RemediationSuggestion(
            title="Fix authentication",
            description="Update auth mechanism"
        )
        issue_with_remediation.add_remediation(remediation)
        
        # Issue without remediation
        issue_without_remediation = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            title="Issue without fix",
            description="Test",
            confidence=0.7,
            impact_score=60
        )
        
        result.add_issue(issue_with_remediation)
        result.add_issue(issue_without_remediation)
        
        issues_with_remediation = result.get_issues_with_remediation()
        assert len(issues_with_remediation) == 1
        assert issues_with_remediation[0] == issue_with_remediation
    
    @pytest.mark.asyncio
    async def test_stream_issues(self):
        """Test streaming issues asynchronously."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add test issues
        issues = []
        for i in range(3):
            issue = Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title=f"Issue {i}",
                description="Test",
                confidence=0.8,
                impact_score=80
            )
            issues.append(issue)
            result.add_issue(issue)
        
        # Stream issues
        streamed_issues = []
        async for issue in result.stream_issues():
            streamed_issues.append(issue)
        
        assert len(streamed_issues) == 3
        assert streamed_issues == issues
    
    def test_get_network_summary(self):
        """Test network analysis summary."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # No traces
        network_summary = result.get_network_summary()
        assert network_summary['traces'] == 0
        assert network_summary['total_hops'] == 0
        assert network_summary['proxy_chains'] == 0
        
        # Add traces
        trace1 = NetworkTrace(
            trace_id="trace-1",
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            port=443,
            total_hops=3,
            proxy_chain_detected=True
        )
        
        trace2 = NetworkTrace(
            trace_id="trace-2",
            source_ip="192.168.1.2",
            destination_ip="1.1.1.1",
            protocol="UDP",
            port=53,
            total_hops=2,
            proxy_chain_detected=False
        )
        
        result.add_network_trace(trace1)
        result.add_network_trace(trace2)
        
        network_summary = result.get_network_summary()
        assert network_summary['traces'] == 2
        assert network_summary['total_hops'] == 5
        assert network_summary['proxy_chains'] == 1
        assert network_summary['average_hops_per_trace'] == 2.5
    
    def test_get_comprehensive_summary(self):
        """Test comprehensive analysis summary."""
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85,
            critical_issues_count=1,
            high_issues_count=2,
            proxy_chain_functional=True,
            oauth_success=True
        )
        context = ExecutionContext(analyzer_version="2.1.0")
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add an issue
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        result.add_issue(issue)
        
        comprehensive = result.get_comprehensive_summary()
        
        assert isinstance(comprehensive, dict)
        assert comprehensive['result_id'] == result.result_id
        assert comprehensive['status'] == AnalysisStatus.SUCCESS.value
        assert comprehensive['overall_score'] == summary.overall_score  # Score may be updated when issues are added
        assert comprehensive['total_issues'] == summary.total_issues_count
        assert comprehensive['high_priority_issues'] == summary.high_priority_issues_count
        assert 'severity_distribution' in comprehensive
        assert 'categories' in comprehensive
        assert 'network_summary' in comprehensive
        assert 'performance' in comprehensive
        assert 'processing' in comprehensive
        assert 'execution' in comprehensive
        assert 'functional_indicators' in comprehensive
        
        functional = comprehensive['functional_indicators']
        assert functional['proxy_chain_functional'] is True
        assert functional['oauth_success'] is True
    
    def test_to_dict(self):
        """Test converting result to dictionary."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(
            summary=summary,
            execution_context=context,
            raw_log_excerpts={"sample": "data"},
            debug_information={"debug": True}
        )
        
        # Include raw data
        result_dict = result.to_dict(include_raw_data=True)
        assert isinstance(result_dict, dict)
        assert 'raw_log_excerpts' in result_dict
        assert 'debug_information' in result_dict
        
        # Exclude raw data
        result_dict = result.to_dict(include_raw_data=False)
        assert 'raw_log_excerpts' not in result_dict
        assert 'debug_information' not in result_dict
    
    def test_to_summary_dict(self):
        """Test converting result to summary dictionary."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=85)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add some data
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        result.add_issue(issue)
        
        trace = NetworkTrace(
            trace_id="trace-123",
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            port=443
        )
        result.add_network_trace(trace)
        
        summary_dict = result.to_summary_dict()
        
        assert isinstance(summary_dict, dict)
        assert summary_dict['result_id'] == result.result_id
        assert 'summary' in summary_dict
        assert 'execution_context' in summary_dict
        assert summary_dict['issues_count'] == 1
        assert summary_dict['network_traces_count'] == 1
        assert 'performance_summary' in summary_dict
        assert 'comprehensive_summary' in summary_dict
    
    def test_finalize_result(self):
        """Test finalizing analysis result."""
        summary = AnalysisSummary(status=AnalysisStatus.SUCCESS, overall_score=100)
        context = ExecutionContext()
        result = AnalysisResult(summary=summary, execution_context=context)
        
        # Add an issue
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Auth issue",
            description="Test",
            confidence=0.8,
            impact_score=80
        )
        result.add_issue(issue)
        
        # Execution should not be completed initially
        assert not context.is_completed
        assert result.processing_stats.processing_time_ms == 0.0
        
        result.finalize_result()
        
        # Should mark execution as completed
        assert context.is_completed
        
        # Should update processing stats
        if context.duration_seconds:
            expected_time = context.duration_seconds * 1000
            assert result.processing_stats.processing_time_ms == expected_time


class TestResultsIntegration:
    """Integration tests for result models working together."""
    
    def test_complete_analysis_workflow(self):
        """Test complete analysis result workflow."""
        # Create execution context
        context = ExecutionContext(
            session_id="session-123",
            analyzer_version="2.1.0",
            input_files=[Path("test.har")],
            components_used=["parser", "detector", "reporter"]
        )
        
        # Create processing stats
        stats = ProcessingStats(
            files_processed=1,
            log_entries_parsed=1000,
            issues_detected=3,
            processing_time_ms=15000.0,
            peak_memory_mb=256.0
        )
        
        # Create performance metrics
        metrics = PerformanceMetrics(
            total_requests=500,
            successful_requests=485,
            average_response_time_ms=150.0,
            error_rate_percent=3.0
        )
        
        # Create summary
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=82,
            proxy_chain_functional=True,
            oauth_success=True,
            analysis_duration_ms=15000.0
        )
        
        # Create result
        result = AnalysisResult(
            summary=summary,
            execution_context=context,
            processing_stats=stats,
            performance_metrics=metrics
        )
        
        # Add issues
        critical_issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.CRITICAL,
            title="Critical auth bypass",
            description="Authentication can be bypassed",
            confidence=0.95,
            impact_score=95
        )
        
        high_issue = Issue(
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            title="Suspicious network activity",
            description="Unusual network patterns detected",
            confidence=0.85,
            impact_score=80
        )
        
        medium_issue = Issue(
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.MEDIUM,
            title="Data exposure",
            description="Sensitive data potentially exposed",
            confidence=0.75,
            impact_score=65
        )
        
        result.add_issue(critical_issue)
        result.add_issue(high_issue)
        result.add_issue(medium_issue)
        
        # Add network traces
        trace = NetworkTrace(
            trace_id="trace-main",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.1",
            protocol="HTTPS",
            port=443,
            total_hops=4,
            proxy_chain_detected=True
        )
        result.add_network_trace(trace)
        
        # Finalize result
        result.finalize_result()
        
        # Verify complete result
        assert result.summary.total_issues_count == 3
        assert result.summary.critical_issues_count == 1
        assert result.summary.high_issues_count == 1
        assert result.summary.medium_issues_count == 1
        assert result.execution_context.is_completed
        
        # Test comprehensive summary
        comprehensive = result.get_comprehensive_summary()
        assert comprehensive['total_issues'] == 3
        assert comprehensive['high_priority_issues'] == 2
        assert comprehensive['status'] == AnalysisStatus.SUCCESS.value
        
        # Test network summary
        network_summary = result.get_network_summary()
        assert network_summary['traces'] == 1
        assert network_summary['proxy_chains'] == 1
        
        # Test serialization
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert len(result_dict['issues']) == 3
        assert len(result_dict['network_traces']) == 1
        
        summary_dict = result.to_summary_dict()
        assert summary_dict['issues_count'] == 3
        assert summary_dict['network_traces_count'] == 1
