"""
Issue and detection models for NetStealth Analyzer.

This module defines models for security issues, detection rules, and remediation
suggestions with enhanced metadata and evidence tracking.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.13+
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, computed_field, model_validator

from .enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..compatibility import override


class IssueLocation(BaseModel):
    """Location information for where an issue was detected."""
    
    file_path: Optional[Path] = Field(None, description="Source file path")
    line_number: Optional[int] = Field(None, ge=1, description="Line number in file")
    column_number: Optional[int] = Field(None, ge=1, description="Column number in line")
    function_name: Optional[str] = Field(None, description="Function or method name")
    url: Optional[str] = Field(None, description="URL where issue occurred")
    request_id: Optional[str] = Field(None, description="Request identifier")
    timestamp: Optional[datetime] = Field(None, description="When issue occurred")
    
    @field_validator('file_path', mode='before')
    @classmethod
    def validate_file_path(cls, v):
        if v is not None and not isinstance(v, Path):
            return Path(v)
        return v
    
    def __str__(self) -> str:
        """String representation of location."""
        parts = []
        if self.file_path:
            parts.append(str(self.file_path))
        if self.line_number:
            parts.append(f"line {self.line_number}")
        if self.url:
            parts.append(f"URL: {self.url}")
        return " | ".join(parts) if parts else "Unknown location"


class IssueEvidence(BaseModel):
    """Evidence supporting an issue detection."""
    
    type: str = Field(..., description="Type of evidence (header, response, log_entry, etc.)")
    description: str = Field(..., description="Human-readable description")
    raw_data: Any = Field(..., description="Raw evidence data")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this evidence")
    source: Optional[str] = Field(None, description="Source of evidence")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @computed_field
    @property
    def confidence_level(self) -> DetectionConfidence:
        """Get confidence level enum from numeric confidence."""
        return DetectionConfidence.from_score(self.confidence)
    
    def to_summary(self) -> str:
        """Get summary string for evidence."""
        return f"{self.type}: {self.description} (confidence: {self.confidence:.2f})"


class IssueMetadata(BaseModel):
    """Extended metadata for issues."""
    
    tags: List[str] = Field(default_factory=list, description="Issue tags")
    references: List[str] = Field(default_factory=list, description="External references (URLs, CVEs)")
    affected_components: List[str] = Field(default_factory=list, description="Affected system components")
    detection_method: Optional[str] = Field(None, description="Method used for detection")
    false_positive_likelihood: float = Field(0.0, ge=0.0, le=1.0, description="Likelihood of false positive")
    business_impact: Optional[str] = Field(None, description="Business impact description")
    technical_impact: Optional[str] = Field(None, description="Technical impact description")
    
    # Compliance and regulatory
    compliance_frameworks: List[str] = Field(default_factory=list, description="Relevant compliance frameworks")
    regulatory_requirements: List[str] = Field(default_factory=list, description="Regulatory requirements")
    
    # Temporal information
    first_seen: Optional[datetime] = Field(None, description="When issue was first detected")
    last_seen: Optional[datetime] = Field(None, description="When issue was last detected")
    occurrence_count: int = Field(1, ge=1, description="Number of times issue occurred")


class RemediationSuggestion(BaseModel):
    """Remediation suggestion for fixing an issue."""
    
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique suggestion ID")
    title: str = Field(..., description="Short remediation title")
    description: str = Field(..., description="Detailed remediation description")
    priority: int = Field(1, ge=1, le=5, description="Priority (1=highest, 5=lowest)")
    effort_level: str = Field("medium", description="Effort required (low, medium, high)")
    
    # Implementation details
    code_fix: Optional[str] = Field(None, description="Code snippet to fix issue")
    configuration_changes: List[str] = Field(default_factory=list, description="Configuration changes needed")
    dependencies: List[str] = Field(default_factory=list, description="Dependencies for fix")
    
    # Validation and testing
    validation_steps: List[str] = Field(default_factory=list, description="Steps to validate fix")
    test_cases: List[str] = Field(default_factory=list, description="Test cases to verify fix")
    
    # Risk assessment
    risk_level: str = Field("low", description="Risk of implementing fix")
    side_effects: List[str] = Field(default_factory=list, description="Potential side effects")
    rollback_plan: Optional[str] = Field(None, description="Plan for rolling back fix")
    
    @field_validator('effort_level')
    @classmethod
    def validate_effort_level(cls, v: str) -> str:
        if v not in ['low', 'medium', 'high']:
            raise ValueError("Effort level must be 'low', 'medium', or 'high'")
        return v
    
    @field_validator('risk_level')
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        if v not in ['low', 'medium', 'high', 'critical']:
            raise ValueError("Risk level must be 'low', 'medium', 'high', or 'critical'")
        return v


class Issue(BaseModel):
    """
    Represents a security or privacy issue detected during analysis.
    
    Enhanced version of the original CriticalIssue with better structure,
    evidence tracking, and remediation support.
    """
    
    # Core identification
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique issue identifier")
    category: IssueCategory = Field(..., description="Issue category")
    severity: SeverityLevel = Field(..., description="Issue severity level")
    
    # Basic information
    title: str = Field(..., description="Short, descriptive title")
    description: str = Field(..., description="Detailed issue description")
    summary: Optional[str] = Field(None, description="Brief summary for reports")
    
    # Detection information
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence (0.0-1.0)")
    detection_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When issue was detected"
    )
    
    # Location and context
    location: Optional[IssueLocation] = Field(None, description="Where issue was found")
    evidence: List[IssueEvidence] = Field(default_factory=list, description="Supporting evidence")
    metadata: IssueMetadata = Field(default_factory=IssueMetadata, description="Extended metadata")
    
    # Impact assessment
    impact_score: int = Field(..., ge=0, le=100, description="Impact score (0-100)")
    exploitability_score: int = Field(0, ge=0, le=100, description="Exploitability score (0-100)")
    
    # Remediation
    remediation_suggestions: List[RemediationSuggestion] = Field(
        default_factory=list,
        description="Suggested fixes"
    )
    
    # Status tracking
    status: str = Field("open", description="Issue status (open, investigating, resolved, false_positive)")
    assigned_to: Optional[str] = Field(None, description="Person assigned to handle issue")
    resolution_notes: Optional[str] = Field(None, description="Notes about resolution")
    
    # Raw data (for debugging and analysis)
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw detection data")
    
    class Config:
        use_enum_values = True
        validate_assignment = True
    
    @computed_field
    @property
    def confidence_level(self) -> DetectionConfidence:
        """Get confidence level enum from numeric confidence."""
        return DetectionConfidence.from_score(self.confidence)
    
    @computed_field
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score based on impact, exploitability, and confidence."""
        # Weighted combination of factors
        base_score = (self.impact_score * 0.4 + self.exploitability_score * 0.3) / 100.0
        confidence_weight = self.confidence * 0.3
        return min(1.0, base_score + confidence_weight)
    
    @computed_field
    @property
    def display_title(self) -> str:
        """Get display-friendly title with category."""
        return f"[{self.category.display_name}] {self.title}"
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed_statuses = ['open', 'investigating', 'resolved', 'false_positive', 'wont_fix']
        if v not in allowed_statuses:
            raise ValueError(f"Status must be one of: {allowed_statuses}")
        return v
    
    def add_evidence(self, evidence: IssueEvidence) -> None:
        """Add evidence to the issue."""
        self.evidence.append(evidence)
        # Update confidence based on new evidence
        if self.evidence:
            avg_confidence = sum(e.confidence for e in self.evidence) / len(self.evidence)
            self.confidence = min(1.0, max(self.confidence, avg_confidence))
    
    def add_remediation(self, suggestion: RemediationSuggestion) -> None:
        """Add remediation suggestion."""
        self.remediation_suggestions.append(suggestion)
        # Sort by priority
        self.remediation_suggestions.sort(key=lambda x: x.priority)
    
    def get_evidence_by_type(self, evidence_type: str) -> List[IssueEvidence]:
        """Get all evidence of a specific type."""
        return [e for e in self.evidence if e.type == evidence_type]
    
    def get_primary_remediation(self) -> Optional[RemediationSuggestion]:
        """Get the highest priority remediation suggestion."""
        if self.remediation_suggestions:
            return min(self.remediation_suggestions, key=lambda x: x.priority)
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(exclude_none=True)
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert to summary dictionary (excluding raw data and detailed evidence)."""
        data = self.model_dump(exclude={'raw_data', 'evidence'})
        data['evidence_count'] = len(self.evidence)
        data['evidence_types'] = list(set(e.type for e in self.evidence))
        return data
    
    def __str__(self) -> str:
        """String representation of issue."""
        return f"{self.severity.value.upper()}: {self.display_title} (confidence: {self.confidence:.2f})"


class DetectionRule(BaseModel):
    """
    Configuration for detection rules used by detectors.
    
    Enhanced version with better pattern matching and metadata support.
    """
    
    # Core identification
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    version: str = Field("1.0.0", description="Rule version")
    
    # Classification
    category: IssueCategory = Field(..., description="Issue category this rule detects")
    severity: SeverityLevel = Field(..., description="Default severity for matches")
    tags: List[str] = Field(default_factory=list, description="Rule tags for organization")
    
    # Detection logic
    pattern: str = Field(..., description="Detection pattern (regex, string, or expression)")
    pattern_type: str = Field("regex", description="Pattern type (regex, string, xpath, jsonpath)")
    case_sensitive: bool = Field(True, description="Whether pattern matching is case sensitive")
    
    # Conditions and filters
    conditions: List[str] = Field(default_factory=list, description="Additional conditions")
    exclude_patterns: List[str] = Field(default_factory=list, description="Patterns to exclude")
    
    # Metadata
    description: str = Field(..., description="Detailed rule description")
    rationale: Optional[str] = Field(None, description="Why this rule is important")
    references: List[str] = Field(default_factory=list, description="External references")
    
    # Configuration
    enabled: bool = Field(True, description="Whether rule is active")
    confidence: Union[float, DetectionConfidence] = Field(0.8, description="Base confidence for matches")
    max_matches: Optional[int] = Field(None, ge=1, description="Maximum matches per analysis")
    
    # Remediation
    default_remediation: Optional[str] = Field(None, description="Default remediation advice")
    code_fix_template: Optional[str] = Field(None, description="Template for code fixes")
    
    # Performance
    timeout_ms: int = Field(5000, ge=100, description="Rule execution timeout in milliseconds")
    priority: int = Field(50, ge=1, le=100, description="Execution priority (1=highest)")
    
    # Metadata
    author: Optional[str] = Field(None, description="Rule author")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Rule creation timestamp"
    )
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    
    class Config:
        use_enum_values = True
        validate_assignment = True
    
    @field_validator('confidence', mode='before')
    @classmethod
    def validate_confidence(cls, v: Union[float, DetectionConfidence]) -> float:
        """Convert DetectionConfidence enum to numeric value if needed."""
        if isinstance(v, DetectionConfidence):
            return v.numeric_value
        elif isinstance(v, (float, int)):
            v = float(v)
            if not (0.0 <= v <= 1.0):
                raise ValueError("Confidence must be between 0.0 and 1.0")
            return v
        elif isinstance(v, str):
            # Try to convert string to DetectionConfidence enum
            try:
                enum_val = DetectionConfidence(v)
                return enum_val.numeric_value
            except ValueError:
                pass
            # Try to convert string to float
            try:
                v = float(v)
                if not (0.0 <= v <= 1.0):
                    raise ValueError("Confidence must be between 0.0 and 1.0")
                return v
            except ValueError:
                pass
        
        raise ValueError(f"Confidence must be a float or DetectionConfidence enum, got {type(v)}: {v}")
    
    @field_validator('pattern_type')
    @classmethod
    def validate_pattern_type(cls, v: str) -> str:
        allowed_types = ['regex', 'string', 'xpath', 'jsonpath', 'custom']
        if v not in allowed_types:
            raise ValueError(f"Pattern type must be one of: {allowed_types}")
        return v
    
    def matches_context(self, context: Dict[str, Any]) -> bool:
        """Check if rule should be applied in given context."""
        # Check if any exclude patterns match
        for exclude_pattern in self.exclude_patterns:
            if exclude_pattern in str(context):
                return False
        
        # Check additional conditions
        for condition in self.conditions:
            # Simple condition evaluation (can be enhanced)
            if not eval(condition, {"context": context}):
                return False
        
        return True
    
    def create_issue_template(self) -> Dict[str, Any]:
        """Create issue template for matches of this rule."""
        return {
            'category': self.category,
            'severity': self.severity,
            'title': f"{self.name} detected",
            'description': self.description,
            'confidence': self.confidence,
            'metadata': {
                'detection_method': f"Rule: {self.id}",
                'rule_version': self.version,
                'tags': self.tags.copy()
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(exclude_none=True)


# Export all models
__all__ = [
    'Issue',
    'IssueEvidence',
    'IssueLocation',
    'IssueMetadata',
    'RemediationSuggestion',
    'DetectionRule',
]
