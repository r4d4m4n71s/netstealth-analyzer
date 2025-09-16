"""Browser configuration detector for TIDAL Stealth Analyzer."""

from typing import Any, Dict, List
from datetime import datetime
from ..models import AnalysisConfig, CriticalIssue, IssueCategory, SeverityLevel


class BrowserDetector:
    """Detector for browser configuration issues."""
    
    def __init__(self, config: AnalysisConfig):
        self.config = config
    
    def detect(self, parsed_data: Dict[str, Any]) -> List[CriticalIssue]:
        """Detect browser configuration issues."""
        issues = []
        
        # Extract browser events from all sources
        browser_events = self._extract_browser_events(parsed_data)
        
        # Check for automation detection
        detection_events = []
        for source_data in parsed_data.get('sources', []):
            if source_data.get('format', '') in ['browser_console', 'chrome_debug']:
                source_detections = source_data.get('data', {}).get('detection_events', [])
                detection_events.extend(source_detections)
        
        if detection_events:
            high_risk_detections = [e for e in detection_events if e.get('risk_level') == 'high']
            
            if high_risk_detections:
                issue = CriticalIssue(
                    id="BROWSER_AUTOMATION_DETECTED",
                    category=IssueCategory.BROWSER_CONFIG,
                    severity=SeverityLevel.CRITICAL,
                    title="Browser Automation Detection",
                    description=f"High-risk automation detection events: {len(high_risk_detections)}",
                    timestamp=datetime.now(),
                    recommendation="Update undetected-chromedriver and stealth settings",
                    code_fix="Use latest undetected-chromedriver with stealth mode",
                    impact_score=95,
                    raw_data={'detections': high_risk_detections[:3]}
                )
                issues.append(issue)
        
        return issues
    
    def _extract_browser_events(self, parsed_data: Dict[str, Any]) -> List[Dict]:
        """Extract browser events from parsed sources."""
        all_events = []
        for source_data in parsed_data.get('sources', []):
            if source_data.get('format', '') in ['browser_console', 'chrome_debug']:
                browser_events = source_data.get('data', {}).get('browser_events', [])
                all_events.extend(browser_events)
        return all_events
