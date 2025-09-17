"""
Analysis results and summary models for NetStealth Analyzer.

This module defines models for analysis results, performance metrics, and
execution context with enhanced async support and streaming capabilities.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.13+
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, AsyncIterator
from uuid import UUID, uuid4
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, computed_field, ConfigDict

from .enums import AnalysisStatus, SeverityLevel, IssueCategory, LogFormat
from .issues import Issue
from .network import NetworkTrace
from ..compatibility import override


class ProcessingStats(BaseModel):
    """Statistics about data processing during analysis."""
    
    # File processing
    files_processed: int = Field(0, ge=0, description="Number of files processed")
    files_failed: int = Field(0, ge=0, description="Number of files that failed processing")
    total_file_size_mb: float = Field(0.0, ge=0.0, description="Total size of processed files")
    
    # Log entry processing
    log_entries_parsed: int = Field(0, ge=0, description="Number of log entries parsed")
    log_entries_skipped: int = Field(0, ge=0, description="Number of log entries skipped")
    parse_errors: int = Field(0, ge=0, description="Number of parsing errors")
    
    # Detection processing
    detectors_executed: int = Field(0, ge=0, description="Number of detectors executed")
    detection_rules_applied: int = Field(0, ge=0, description="Number of detection rules applied")
    issues_detected: int = Field(0, ge=0, description="Total issues detected")
    false_positives_filtered: int = Field(0, ge=0, description="False positives filtered out")
    
    # Performance metrics
    processing_time_ms: float = Field(0.0, ge=0.0, description="Total processing time")
    parsing_time_ms: float = Field(0.0, ge=0.0, description="Time spent parsing")
    detection_time_ms: float = Field(0.0, ge=0.0, description="Time spent on detection")
    reporting_time_ms: float = Field(0.0, ge=0.0, description="Time spent generating reports")
    
    # Memory usage
    peak_memory_mb: float = Field(0.0, ge=0.0, description="Peak memory usage")
    average_memory_mb: float = Field(0.0, ge=0.0, description="Average memory usage")
    
    @computed_field
    @property
    def success_rate(self) -> float:
        """Calculate overall processing success rate."""
        total_files = self.files_processed + self.files_failed
        if total_files == 0:
            return 1.0
        return self.files_processed / total_files
    
    @computed_field
    @property
    def parse_success_rate(self) -> float:
        """Calculate log parsing success rate."""
        total_entries = self.log_entries_parsed + self.log_entries_skipped + self.parse_errors
        if total_entries == 0:
            return 1.0
        return self.log_entries_parsed / total_entries
    
    @computed_field
    @property
    def processing_speed_entries_per_second(self) -> float:
        """Calculate processing speed in entries per second."""
        if self.processing_time_ms == 0:
            return 0.0
        return (self.log_entries_parsed / self.processing_time_ms) * 1000
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        return {
            'success_rate': self.success_rate,
            'parse_success_rate': self.parse_success_rate,
            'processing_speed': self.processing_speed_entries_per_second,
            'total_time_seconds': self.processing_time_ms / 1000,
            'peak_memory_mb': self.peak_memory_mb,
            'files_processed': self.files_processed,
            'issues_detected': self.issues_detected
        }


class PerformanceMetrics(BaseModel):
    """
    Performance-related metrics for network operations.
    
    Enhanced version with detailed timing and quality metrics.
    """
    
    # Request metrics
    total_requests: int = Field(0, ge=0, description="Total number of requests")
    successful_requests: int = Field(0, ge=0, description="Number of successful requests")
    failed_requests: int = Field(0, ge=0, description="Number of failed requests")
    timeout_requests: int = Field(0, ge=0, description="Number of timed out requests")
    
    # Response time metrics
    average_response_time_ms: float = Field(0.0, ge=0.0, description="Average response time")
    median_response_time_ms: float = Field(0.0, ge=0.0, description="Median response time")
    min_response_time_ms: float = Field(0.0, ge=0.0, description="Minimum response time")
    max_response_time_ms: float = Field(0.0, ge=0.0, description="Maximum response time")
    p95_response_time_ms: float = Field(0.0, ge=0.0, description="95th percentile response time")
    p99_response_time_ms: float = Field(0.0, ge=0.0, description="99th percentile response time")
    
    # Throughput metrics
    requests_per_second: float = Field(0.0, ge=0.0, description="Requests per second")
    bytes_per_second: float = Field(0.0, ge=0.0, description="Bytes transferred per second")
    
    # Error metrics
    error_rate_percent: float = Field(0.0, ge=0.0, le=100.0, description="Error rate percentage")
    timeout_rate_percent: float = Field(0.0, ge=0.0, le=100.0, description="Timeout rate percentage")
    
    # Connection metrics
    connection_time_ms: float = Field(0.0, ge=0.0, description="Average connection establishment time")
    ssl_handshake_time_ms: float = Field(0.0, ge=0.0, description="Average SSL handshake time")
    dns_lookup_time_ms: float = Field(0.0, ge=0.0, description="Average DNS lookup time")
    
    # Data transfer metrics
    total_bytes_sent: int = Field(0, ge=0, description="Total bytes sent")
    total_bytes_received: int = Field(0, ge=0, description="Total bytes received")
    compression_ratio: float = Field(1.0, ge=0.0, description="Compression ratio (if applicable)")
    
    @computed_field
    @property
    def success_rate_percent(self) -> float:
        """Calculate success rate percentage."""
        if self.total_requests == 0:
            return 100.0
        return (self.successful_requests / self.total_requests) * 100.0
    
    @computed_field
    @property
    def total_bytes_transferred(self) -> int:
        """Get total bytes transferred."""
        return self.total_bytes_sent + self.total_bytes_received
    
    @computed_field
    @property
    def average_request_size_bytes(self) -> float:
        """Calculate average request size."""
        if self.total_requests == 0:
            return 0.0
        return self.total_bytes_sent / self.total_requests
    
    @computed_field
    @property
    def average_response_size_bytes(self) -> float:
        """Calculate average response size."""
        if self.successful_requests == 0:
            return 0.0
        return self.total_bytes_received / self.successful_requests
    
    def get_quality_assessment(self) -> Dict[str, str]:
        """Get quality assessment based on metrics."""
        assessment = {}
        
        # Response time assessment
        if self.average_response_time_ms < 100:
            assessment['response_time'] = 'excellent'
        elif self.average_response_time_ms < 500:
            assessment['response_time'] = 'good'
        elif self.average_response_time_ms < 2000:
            assessment['response_time'] = 'acceptable'
        else:
            assessment['response_time'] = 'poor'
        
        # Success rate assessment
        if self.success_rate_percent >= 99:
            assessment['reliability'] = 'excellent'
        elif self.success_rate_percent >= 95:
            assessment['reliability'] = 'good'
        elif self.success_rate_percent >= 90:
            assessment['reliability'] = 'acceptable'
        else:
            assessment['reliability'] = 'poor'
        
        # Error rate assessment
        if self.error_rate_percent < 1:
            assessment['error_rate'] = 'excellent'
        elif self.error_rate_percent < 5:
            assessment['error_rate'] = 'good'
        elif self.error_rate_percent < 10:
            assessment['error_rate'] = 'acceptable'
        else:
            assessment['error_rate'] = 'poor'
        
        return assessment


class ExecutionContext(BaseModel):
    """Context information about analysis execution."""
    
    # Execution identification
    execution_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique execution ID")
    session_id: Optional[str] = Field(None, description="Session identifier")
    correlation_id: Optional[str] = Field(None, description="Correlation identifier")
    
    # Timing information
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Execution start time")
    end_time: Optional[datetime] = Field(None, description="Execution end time")
    
    # Environment information
    analyzer_version: str = Field("2.0.0", description="Analyzer version used")
    python_version: str = Field("", description="Python version")
    platform: str = Field("", description="Platform information")
    hostname: str = Field("", description="Hostname where analysis ran")
    
    # Configuration
    configuration_hash: Optional[str] = Field(None, description="Hash of configuration used")
    configuration_summary: Dict[str, Any] = Field(default_factory=dict, description="Key configuration settings")
    
    # Input information
    input_files: List[Path] = Field(default_factory=list, description="Input files processed")
    input_formats: List[LogFormat] = Field(default_factory=list, description="Input file formats")
    
    # Processing information
    components_used: List[str] = Field(default_factory=list, description="Components used in analysis")
    plugins_loaded: List[str] = Field(default_factory=list, description="Plugins loaded")
    
    # Resource usage
    max_memory_usage_mb: float = Field(0.0, ge=0.0, description="Maximum memory usage")
    cpu_time_seconds: float = Field(0.0, ge=0.0, description="CPU time used")
    
    @field_validator('input_files', mode='before')
    @classmethod
    def validate_input_files(cls, v):
        if isinstance(v, list):
            return [Path(f) if not isinstance(f, Path) else f for f in v]
        return v
    
    @computed_field
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate execution duration in seconds."""
        if self.end_time is None:
            return None
        delta = self.end_time - self.start_time
        return delta.total_seconds()
    
    @computed_field
    @property
    def is_completed(self) -> bool:
        """Check if execution is completed."""
        return self.end_time is not None
    
    def mark_completed(self) -> None:
        """Mark execution as completed."""
        if self.end_time is None:
            self.end_time = datetime.now(timezone.utc)
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get execution summary."""
        return {
            'execution_id': self.execution_id,
            'duration_seconds': self.duration_seconds,
            'analyzer_version': self.analyzer_version,
            'input_files_count': len(self.input_files),
            'components_used': self.components_used,
            'plugins_loaded': self.plugins_loaded,
            'max_memory_mb': self.max_memory_usage_mb,
            'completed': self.is_completed
        }


class AnalysisSummary(BaseModel):
    """
    High-level summary of analysis results.
    
    Enhanced version with better categorization and scoring.
    """
    
    # Overall status
    status: AnalysisStatus = Field(..., description="Overall analysis status")
    overall_score: int = Field(..., ge=0, le=100, description="Overall success score (0-100)")
    
    # Issue counts by severity
    critical_issues_count: int = Field(0, ge=0, description="Number of critical issues")
    high_issues_count: int = Field(0, ge=0, description="Number of high severity issues")
    medium_issues_count: int = Field(0, ge=0, description="Number of medium severity issues")
    low_issues_count: int = Field(0, ge=0, description="Number of low severity issues")
    info_issues_count: int = Field(0, ge=0, description="Number of info level issues")
    
    # Issue counts by category
    issues_by_category: Dict[str, int] = Field(default_factory=dict, description="Issues grouped by category")
    
    # Functional assessments
    proxy_chain_functional: bool = Field(False, description="Is proxy chain working properly")
    oauth_success: bool = Field(False, description="Did OAuth authentication succeed")
    antibot_bypass_success: bool = Field(False, description="Was anti-bot protection bypassed")
    geographic_masking_active: bool = Field(False, description="Is geographic masking working")
    tls_security_adequate: bool = Field(False, description="Is TLS security adequate")
    
    # Risk assessment
    overall_risk_level: str = Field("unknown", description="Overall risk level")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score (0.0-1.0)")
    
    # Performance summary
    analysis_duration_ms: float = Field(0.0, ge=0.0, description="Time taken for analysis")
    processing_efficiency: float = Field(0.0, ge=0.0, le=1.0, description="Processing efficiency score")
    
    # Metadata
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Analysis timestamp")
    
    @computed_field
    @property
    def total_issues_count(self) -> int:
        """Calculate total number of issues."""
        return (self.critical_issues_count + self.high_issues_count + 
                self.medium_issues_count + self.low_issues_count + self.info_issues_count)
    
    @computed_field
    @property
    def high_priority_issues_count(self) -> int:
        """Get count of high priority issues (critical + high)."""
        return self.critical_issues_count + self.high_issues_count
    
    @computed_field
    @property
    def success_indicators_count(self) -> int:
        """Count successful functional indicators."""
        indicators = [
            self.proxy_chain_functional,
            self.oauth_success,
            self.antibot_bypass_success,
            self.geographic_masking_active,
            self.tls_security_adequate
        ]
        return sum(1 for indicator in indicators if indicator)
    
    @field_validator('overall_risk_level')
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        allowed_levels = ['safe', 'low', 'medium', 'high', 'critical', 'unknown']
        if v not in allowed_levels:
            raise ValueError(f"Risk level must be one of: {allowed_levels}")
        return v
    
    def update_from_issues(self, issues: List[Issue]) -> None:
        """Update summary statistics from list of issues."""
        # Reset counts
        self.critical_issues_count = 0
        self.high_issues_count = 0
        self.medium_issues_count = 0
        self.low_issues_count = 0
        self.info_issues_count = 0
        self.issues_by_category = {}
        
        # Count issues by severity
        for issue in issues:
            if issue.severity == SeverityLevel.CRITICAL:
                self.critical_issues_count += 1
            elif issue.severity == SeverityLevel.HIGH:
                self.high_issues_count += 1
            elif issue.severity == SeverityLevel.MEDIUM:
                self.medium_issues_count += 1
            elif issue.severity == SeverityLevel.LOW:
                self.low_issues_count += 1
            elif issue.severity == SeverityLevel.INFO:
                self.info_issues_count += 1
            
            # Count by category
            if hasattr(issue.category, 'value'):
                category = issue.category.value
            else:
                category = str(issue.category)
            self.issues_by_category[category] = self.issues_by_category.get(category, 0) + 1
        
        # Update overall score based on issues
        self._calculate_overall_score()
    
    def _calculate_overall_score(self) -> None:
        """Calculate overall score based on issues and functional indicators."""
        # Start with perfect score
        score = 100
        
        # Deduct points for issues
        score -= self.critical_issues_count * 20
        score -= self.high_issues_count * 10
        score -= self.medium_issues_count * 5
        score -= self.low_issues_count * 2
        score -= self.info_issues_count * 1
        
        # Add points for successful functional indicators
        score += self.success_indicators_count * 5
        
        # Ensure score is within bounds
        self.overall_score = max(0, min(100, score))
    
    def get_severity_distribution(self) -> Dict[str, float]:
        """Get percentage distribution of issues by severity."""
        total = self.total_issues_count
        if total == 0:
            return {severity.value: 0.0 for severity in SeverityLevel}
        
        return {
            SeverityLevel.CRITICAL.value: (self.critical_issues_count / total) * 100,
            SeverityLevel.HIGH.value: (self.high_issues_count / total) * 100,
            SeverityLevel.MEDIUM.value: (self.medium_issues_count / total) * 100,
            SeverityLevel.LOW.value: (self.low_issues_count / total) * 100,
            SeverityLevel.INFO.value: (self.info_issues_count / total) * 100,
        }


class AnalysisResult(BaseModel):
    """
    Complete analysis results container.
    
    Enhanced version with better organization, streaming support, and async capabilities.
    """
    
    model_config = ConfigDict(use_enum_values=True, validate_assignment=True)
    
    # Core identification
    result_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique result identifier")
    
    # Summary information
    summary: AnalysisSummary = Field(..., description="High-level analysis summary")
    execution_context: ExecutionContext = Field(..., description="Execution context information")
    
    # Detailed findings
    issues: List[Issue] = Field(default_factory=list, description="All detected issues")
    network_traces: List[NetworkTrace] = Field(default_factory=list, description="Network traces")
    
    # Performance and processing data
    performance_metrics: PerformanceMetrics = Field(default_factory=PerformanceMetrics, description="Performance metrics")
    processing_stats: ProcessingStats = Field(default_factory=ProcessingStats, description="Processing statistics")
    
    # Optional enhanced data
    session_timeline: Optional[List[Dict[str, Any]]] = Field(None, description="Timeline of events")
    fingerprint_analysis: Optional[Dict[str, Any]] = Field(None, description="Fingerprint analysis results")
    remediation_plan: Optional[Dict[str, Any]] = Field(None, description="Automated remediation plan")
    
    # Raw data (if requested)
    raw_log_excerpts: Dict[str, Any] = Field(default_factory=dict, description="Raw log excerpts")
    debug_information: Dict[str, Any] = Field(default_factory=dict, description="Debug information")
    
    def add_issue(self, issue: Issue) -> None:
        """Add an issue to the results."""
        self.issues.append(issue)
        # Update summary statistics
        self.summary.update_from_issues(self.issues)
    
    def add_network_trace(self, trace: NetworkTrace) -> None:
        """Add a network trace to the results."""
        self.network_traces.append(trace)
    
    def get_issues_by_severity(self, severity: SeverityLevel) -> List[Issue]:
        """Get all issues with specific severity level."""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_issues_by_category(self, category: IssueCategory) -> List[Issue]:
        """Get all issues in specific category."""
        return [issue for issue in self.issues if issue.category == category]
    
    def get_high_priority_issues(self) -> List[Issue]:
        """Get critical and high severity issues."""
        return [issue for issue in self.issues 
                if issue.severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH}]
    
    def get_issues_with_remediation(self) -> List[Issue]:
        """Get issues that have remediation suggestions."""
        return [issue for issue in self.issues if issue.remediation_suggestions]
    
    async def stream_issues(self) -> AsyncIterator[Issue]:
        """Stream issues asynchronously."""
        for issue in self.issues:
            yield issue
    
    def get_network_summary(self) -> Dict[str, Any]:
        """Get network analysis summary."""
        if not self.network_traces:
            return {'traces': 0, 'total_hops': 0, 'proxy_chains': 0}
        
        total_hops = sum(trace.total_hops for trace in self.network_traces)
        proxy_chains = sum(1 for trace in self.network_traces if trace.proxy_chain_detected)
        
        return {
            'traces': len(self.network_traces),
            'total_hops': total_hops,
            'proxy_chains': proxy_chains,
            'average_hops_per_trace': total_hops / len(self.network_traces) if self.network_traces else 0
        }
    
    def get_comprehensive_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary."""
        return {
            'result_id': self.result_id,
            'status': self.summary.status.value,
            'overall_score': self.summary.overall_score,
            'total_issues': self.summary.total_issues_count,
            'high_priority_issues': self.summary.high_priority_issues_count,
            'severity_distribution': self.summary.get_severity_distribution(),
            'categories': list(self.summary.issues_by_category.keys()),
            'network_summary': self.get_network_summary(),
            'performance': self.performance_metrics.get_quality_assessment(),
            'processing': self.processing_stats.get_performance_summary(),
            'execution': self.execution_context.get_execution_summary(),
            'functional_indicators': {
                'proxy_chain_functional': self.summary.proxy_chain_functional,
                'oauth_success': self.summary.oauth_success,
                'antibot_bypass_success': self.summary.antibot_bypass_success,
                'geographic_masking_active': self.summary.geographic_masking_active,
                'tls_security_adequate': self.summary.tls_security_adequate,
            }
        }
    
    def to_dict(self, include_raw_data: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        exclude_fields = set()
        if not include_raw_data:
            exclude_fields.update({'raw_log_excerpts', 'debug_information'})
        
        return self.model_dump(exclude=exclude_fields, exclude_none=True)
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert to summary dictionary (minimal data)."""
        return {
            'result_id': self.result_id,
            'summary': self.summary.model_dump(),
            'execution_context': self.execution_context.get_execution_summary(),
            'issues_count': len(self.issues),
            'network_traces_count': len(self.network_traces),
            'performance_summary': self.performance_metrics.get_quality_assessment(),
            'comprehensive_summary': self.get_comprehensive_summary()
        }
    
    def finalize_result(self) -> None:
        """Finalize the analysis result."""
        # Mark execution as completed
        self.execution_context.mark_completed()
        
        # Update final statistics
        self.summary.update_from_issues(self.issues)
        
        # Set final processing stats
        if self.execution_context.duration_seconds:
            self.processing_stats.processing_time_ms = self.execution_context.duration_seconds * 1000


# Export all models
__all__ = [
    'ProcessingStats',
    'PerformanceMetrics',
    'ExecutionContext',
    'AnalysisSummary',
    'AnalysisResult',
]
