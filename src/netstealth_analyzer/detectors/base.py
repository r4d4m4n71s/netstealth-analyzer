"""
Base interfaces and classes for issue detectors.

This module defines the abstract base class for all detectors
and common functionality used across the detection system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Union
from uuid import uuid4

from ..models.issues import Issue, IssueEvidence, DetectionRule
from ..models.enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..models.network import NetworkTrace
from ..core.events import EventBus


@dataclass
class DetectionContext:
    """Context information for detection operations."""
    
    # Source data
    network_traces: List[NetworkTrace]
    service_domains: List[str]
    target_geography: Optional[Dict[str, Any]] = None
    
    # Analysis settings
    strict_mode: bool = False
    confidence_threshold: float = 0.7
    
    # Session information
    session_id: Optional[str] = None
    analysis_timestamp: Optional[datetime] = None
    
    # Additional context
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.metadata is None:
            self.metadata = {}
        if self.analysis_timestamp is None:
            self.analysis_timestamp = datetime.now(timezone.utc)


@dataclass
class DetectionResult:
    """Result of a detection operation."""
    
    detector_name: str
    detector_version: str
    execution_time_ms: float
    issues_found: List[Issue]
    detection_rules_applied: List[DetectionRule]
    statistics: Dict[str, Any]
    errors: List[Dict[str, Any]]
    
    @property
    def is_successful(self) -> bool:
        """Check if detection completed successfully."""
        return len(self.errors) == 0
    
    @property
    def issue_count(self) -> int:
        """Get total number of issues found."""
        return len(self.issues_found)
    
    @property
    def high_severity_count(self) -> int:
        """Get count of high severity issues."""
        return len([i for i in self.issues_found if i.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]])
    
    def get_issues_by_category(self, category: IssueCategory) -> List[Issue]:
        """Get issues by category."""
        return [i for i in self.issues_found if i.category == category]
    
    def get_issues_by_severity(self, min_severity: SeverityLevel) -> List[Issue]:
        """Get issues at or above minimum severity level."""
        return [i for i in self.issues_found if i.severity.numeric_value >= min_severity.numeric_value]


class IDetector(ABC):
    """Abstract base class for all issue detectors."""
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """
        Initialize detector.
        
        Args:
            event_bus: Optional event bus for progress notifications
        """
        self.event_bus = event_bus
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get detector name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Get detector version."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Get detector description."""
        pass
    
    @property
    @abstractmethod
    def categories(self) -> List[IssueCategory]:
        """Get issue categories this detector can identify."""
        pass
    
    @property
    @abstractmethod
    def detection_rules(self) -> List[DetectionRule]:
        """Get detection rules used by this detector."""
        pass
    
    @abstractmethod
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found issues and statistics
            
        Raises:
            ValueError: If context is invalid
            RuntimeError: If detection fails
        """
        pass
    
    @abstractmethod
    async def stream_detect(
        self, 
        context: DetectionContext
    ) -> AsyncIterator[Issue]:
        """
        Perform detection and yield issues as they're found.
        
        Args:
            context: Detection context with traces and configuration
            
        Yields:
            Issue objects as they're detected
            
        Raises:
            ValueError: If context is invalid
            RuntimeError: If detection fails
        """
        pass
    
    async def validate_context(self, context: DetectionContext) -> bool:
        """
        Validate detection context.
        
        Args:
            context: Detection context to validate
            
        Returns:
            True if context is valid for this detector
        """
        # Basic validation - subclasses can override for specific requirements
        if not context.network_traces:
            return False
        if not context.service_domains:
            return False
        return True
    
    async def _emit_progress(self, event_type: str, data: Any = None) -> None:
        """
        Emit progress event if event bus is available.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        if self.event_bus:
            await self.event_bus.emit(event_type, data)
    
    def _create_issue(
        self,
        title: str,
        description: str,
        category: IssueCategory,
        severity: SeverityLevel,
        confidence: DetectionConfidence,
        evidence: List[IssueEvidence],
        metadata: Optional[Dict[str, Any]] = None,
        remediation_suggestions: Optional[List[str]] = None
    ) -> Issue:
        """
        Create an issue with standard formatting.
        
        Args:
            title: Issue title
            description: Detailed description
            category: Issue category
            severity: Severity level
            confidence: Detection confidence
            evidence: Supporting evidence
            metadata: Additional metadata
            remediation_suggestions: Suggested fixes
            
        Returns:
            Formatted Issue object
        """
        from ..models.issues import RemediationSuggestion
        
        remediation_objects = []
        if remediation_suggestions:
            for suggestion in remediation_suggestions:
                remediation_objects.append(RemediationSuggestion(
                    title=f"Fix {category.value} issue",
                    description=suggestion,
                    effort_level="medium"
                ))
        
        # Convert DetectionConfidence enum to float if needed
        confidence_value = confidence.numeric_value if hasattr(confidence, 'numeric_value') else float(confidence)
        
        # Separate rule_id from other metadata
        raw_data = {}
        issue_metadata = {'detection_method': self.name}
        
        if metadata:
            # Extract rule_id for raw_data, keep other metadata
            rule_id = metadata.pop('rule_id', None)
            if rule_id:
                raw_data['rule_id'] = rule_id
            issue_metadata.update(metadata)
        
        return Issue(
            id=str(uuid4()),
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence_value,
            impact_score=75,  # Default impact score
            evidence=evidence,
            detection_timestamp=datetime.now(timezone.utc),
            remediation_suggestions=remediation_objects,
            metadata=issue_metadata,
            raw_data=raw_data
        )
    
    def _create_evidence(
        self,
        evidence_type: str,
        description: str,
        value: Any,
        source: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        confidence: float = 0.8
    ) -> IssueEvidence:
        """
        Create evidence with standard formatting.
        
        Args:
            evidence_type: Type of evidence
            description: Evidence description
            value: Evidence value
            source: Source of evidence
            metadata: Additional metadata
            confidence: Confidence in this evidence (0.0-1.0)
            
        Returns:
            Formatted IssueEvidence object
        """
        return IssueEvidence(
            type=evidence_type,
            description=description,
            raw_data=value,
            confidence=confidence,
            source=source or self.name,
            metadata=metadata or {}
        )


class BaseDetector(IDetector):
    """Base implementation with common functionality."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        confidence_threshold: float = 0.7
    ):
        """
        Initialize base detector.
        
        Args:
            event_bus: Optional event bus for progress notifications
            confidence_threshold: Minimum confidence threshold for issues
        """
        super().__init__(event_bus)
        self.confidence_threshold = confidence_threshold
        
        # Common detection patterns
        self.ip_detection_services = [
            'httpbin.org',
            'whatismyipaddress.com', 
            'ipinfo.io',
            'iplocation.net',
            'api.ipify.org',
            'checkip.amazonaws.com',
            'icanhazip.com',
            'ifconfig.me',
            'myexternalip.com',
        ]
        
        # Common proxy-revealing headers
        self.proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP', 
            'Via',
            'X-Proxy-Authorization',
            'Proxy-Authorization',
            'X-Forwarded-Proto',
            'X-Forwarded-Host',
            'X-Forwarded-Server',
            'X-Cluster-Client-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
        ]
    
    async def stream_detect(
        self, 
        context: DetectionContext
    ) -> AsyncIterator[Issue]:
        """
        Default implementation that runs full detection and yields results.
        
        Subclasses can override for true streaming detection.
        """
        result = await self.detect(context)
        for issue in result.issues_found:
            yield issue
    
    def _is_service_domain(self, domain: str, service_domains: List[str]) -> bool:
        """Check if domain is service-related."""
        if not domain or not service_domains:
            return False
        return any(service_domain in domain for service_domain in service_domains)
    
    def _is_ip_detection_service(self, domain: str) -> bool:
        """Check if domain is an IP detection service."""
        if not domain:
            return False
        return any(service in domain for service in self.ip_detection_services)
    
    def _has_proxy_headers(self, headers: List[Dict[str, str]]) -> bool:
        """Check if headers contain proxy-revealing information."""
        if not headers:
            return False
        
        header_names = [h.get('name', '').lower() for h in headers]
        return any(proxy_header.lower() in header_names for proxy_header in self.proxy_headers)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        if not url:
            return ""
        
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return ""
    
    def _is_suspicious_timing(self, timing_ms: float) -> bool:
        """Check if timing indicates potential issues."""
        # Very fast responses might indicate caching or detection
        # Very slow responses might indicate proxy/tunnel issues
        return timing_ms < 10 or timing_ms > 30000
    
    def _calculate_confidence(
        self, 
        evidence_count: int, 
        total_traces: int,
        base_confidence: float = 0.5
    ) -> DetectionConfidence:
        """
        Calculate detection confidence based on evidence.
        
        Args:
            evidence_count: Number of supporting evidence items
            total_traces: Total number of traces analyzed
            base_confidence: Base confidence level
            
        Returns:
            DetectionConfidence level
        """
        if total_traces == 0:
            return DetectionConfidence.LOW
        
        evidence_ratio = evidence_count / total_traces
        confidence_score = base_confidence + (evidence_ratio * 0.4)
        
        # Cap at reasonable maximum
        confidence_score = min(0.95, confidence_score)
        
        return DetectionConfidence.from_score(confidence_score)
    
    def _init_statistics(self) -> Dict[str, Any]:
        """Initialize statistics dictionary."""
        return {
            'traces_analyzed': 0,
            'issues_found': 0,
            'high_confidence_issues': 0,
            'evidence_items_collected': 0,
            'processing_time_ms': 0,
            'detection_rules_triggered': 0,
        }
    
    def _finalize_statistics(
        self, 
        stats: Dict[str, Any], 
        issues: List[Issue],
        start_time: float
    ) -> None:
        """
        Finalize statistics with calculated values.
        
        Args:
            stats: Statistics dictionary to update
            issues: List of detected issues
            start_time: Detection start time
        """
        import time
        
        stats['issues_found'] = len(issues)
        stats['processing_time_ms'] = (time.time() - start_time) * 1000
        
        # Count high confidence issues
        stats['high_confidence_issues'] = len([
            i for i in issues 
            if i.confidence in [DetectionConfidence.HIGH, DetectionConfidence.VERY_HIGH]
        ])
        
        # Count evidence items
        stats['evidence_items_collected'] = sum(len(i.evidence) for i in issues)
        
        # Calculate detection rate
        if stats['traces_analyzed'] > 0:
            stats['issue_detection_rate'] = (stats['issues_found'] / stats['traces_analyzed']) * 100
        else:
            stats['issue_detection_rate'] = 0
    
    def _get_request_data(self, trace: NetworkTrace):
        """
        Extract request data from trace based on protocol.
        
        Args:
            trace: Network trace to extract request data from
            
        Returns:
            Request data object or None if not available
        """
        # First check for direct trace.request access (test mocks and legacy)
        if hasattr(trace, 'request') and trace.request:
            return trace.request
        
        # Try new protocol-aware architecture
        if hasattr(trace, 'is_http') and callable(trace.is_http) and trace.is_http():
            if hasattr(trace, 'http_data') and trace.http_data and hasattr(trace.http_data, 'request'):
                return trace.http_data.request
        
        # Fallback to metadata-based request data
        if hasattr(trace, 'metadata') and trace.metadata:
            http_request = trace.metadata.get('http_request')
            if http_request:
                # Create a simple object to mimic request structure
                class MetadataRequest:
                    def __init__(self, data):
                        self.url = data.get('url', '')
                        self.method = data.get('method', 'GET')
                        self.headers = data.get('headers', [])
                        self.body = data.get('body')
                
                return MetadataRequest(http_request)
        
        return None
    
    def _get_response_data(self, trace: NetworkTrace):
        """
        Extract response data from trace based on protocol.
        
        Args:
            trace: Network trace to extract response data from
            
        Returns:
            Response data object or None if not available
        """
        # First check for direct trace.response access (test mocks and legacy)
        if hasattr(trace, 'response') and trace.response:
            return trace.response
        
        # Try new protocol-aware architecture
        if hasattr(trace, 'is_http') and callable(trace.is_http) and trace.is_http():
            if hasattr(trace, 'http_data') and trace.http_data and hasattr(trace.http_data, 'response'):
                return trace.http_data.response
        
        # Fallback to metadata-based response data
        if hasattr(trace, 'metadata') and trace.metadata:
            http_response = trace.metadata.get('http_response')
            if http_response:
                # Create a simple object to mimic response structure
                class MetadataResponse:
                    def __init__(self, data):
                        self.status_code = data.get('status_code', 200)
                        self.headers = data.get('headers', [])
                        self.body = data.get('body')
                
                return MetadataResponse(http_response)
        
        return None
    
    def _get_timing_data(self, trace: NetworkTrace):
        """
        Extract timing data from trace based on protocol.
        
        Args:
            trace: Network trace to extract timing data from
            
        Returns:
            Timing data object or None if not available
        """
        if trace.is_http() and trace.http_data:
            return trace.http_data.timing
        return None
    
    def _has_http_data(self, trace: NetworkTrace) -> bool:
        """
        Check if trace has HTTP request/response data.
        
        Args:
            trace: Network trace to check
            
        Returns:
            True if trace has HTTP data, False otherwise
        """
        return trace.is_http() and trace.http_data is not None
    
    def _get_headers_from_trace(self, trace: NetworkTrace) -> List[Dict[str, str]]:
        """
        Extract headers from trace based on protocol.
        
        Args:
            trace: Network trace to extract headers from
            
        Returns:
            List of header dictionaries or empty list if not available
        """
        request = self._get_request_data(trace)
        if request and request.headers:
            return request.headers
        return []
    
    def _get_response_body(self, trace: NetworkTrace) -> Optional[str]:
        """
        Extract response body from trace based on protocol.
        
        Args:
            trace: Network trace to extract response body from
            
        Returns:
            Response body string or None if not available
        """
        response = self._get_response_data(trace)
        if response and response.body:
            return str(response.body)
        return None
    
    def _get_status_code(self, trace: NetworkTrace) -> Optional[int]:
        """
        Extract status code from trace based on protocol.
        
        Args:
            trace: Network trace to extract status code from
            
        Returns:
            Status code integer or None if not available
        """
        response = self._get_response_data(trace)
        if response:
            return response.status_code
        return None
    
    def _get_request_url(self, trace: NetworkTrace) -> Optional[str]:
        """
        Extract request URL from trace based on protocol.
        
        Args:
            trace: Network trace to extract URL from
            
        Returns:
            Request URL string or None if not available
        """
        request = self._get_request_data(trace)
        if request:
            return request.url
        return None
