"""Network anomaly detector for Stealth Analyzer."""

from typing import Any, Dict, List
from datetime import datetime
from ..models import AnalysisConfig, CriticalIssue, IssueCategory, SeverityLevel


class NetworkDetector:
    """Detector for network anomalies and performance issues."""
    
    def __init__(self, config: AnalysisConfig):
        self.config = config
    
    def detect(self, parsed_data: Dict[str, Any]) -> List[CriticalIssue]:
        """Detect network anomalies and performance issues."""
        issues = []
        
        # Extract network errors from all sources
        all_errors = []
        for source_data in parsed_data.get('sources', []):
            errors = source_data.get('data', {}).get('errors', [])
            network_errors = source_data.get('data', {}).get('network_errors', [])
            all_errors.extend(errors + network_errors)
        
        # Check for connection failures
        connection_failures = [e for e in all_errors 
                             if 'connection' in str(e).lower() or 'timeout' in str(e).lower()]
        
        if len(connection_failures) > 5:  # Threshold for concern
            issue = CriticalIssue(
                id="NETWORK_CONNECTION_ISSUES",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.HIGH,
                title="Network Connection Issues Detected",
                description=f"Multiple connection failures detected: {len(connection_failures)} occurrences",
                timestamp=datetime.now(),
                recommendation="Check network stability and proxy configuration",
                code_fix="Review proxy settings and network connectivity",
                impact_score=75,
                raw_data={'failure_count': len(connection_failures)}
            )
            issues.append(issue)
        
        return issues
