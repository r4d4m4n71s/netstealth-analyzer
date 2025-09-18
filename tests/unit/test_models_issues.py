"""
Unit tests for NetStealth Analyzer issue models.

Tests the Issue, IssueEvidence, IssueLocation, IssueMetadata, 
RemediationSuggestion, and DetectionRule models with comprehensive
coverage of validation, serialization, and business logic.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
from typing import Dict, Any

from src.netstealth_analyzer.models.issues import (
    Issue,
    IssueEvidence,
    IssueLocation,
    IssueMetadata,
    RemediationSuggestion,
    DetectionRule
)
from src.netstealth_analyzer.models.enums import (
    SeverityLevel,
    IssueCategory,
    DetectionConfidence
)


class TestIssueLocation:
    """Test IssueLocation model."""
    
    def test_location_creation_minimal(self):
        """Test creating location with minimal data."""
        location = IssueLocation()
        
        assert location.file_path is None
        assert location.line_number is None
        assert location.column_number is None
        assert location.function_name is None
        assert location.url is None
        assert location.request_id is None
        assert location.timestamp is None
    
    def test_location_creation_full(self):
        """Test creating location with all data."""
        timestamp = datetime.now(timezone.utc)
        location = IssueLocation(
            file_path=Path("test.py"),
            line_number=42,
            column_number=10,
            function_name="test_function",
            url="https://example.com/test",
            request_id="req-123",
            timestamp=timestamp
        )
        
        assert location.file_path == Path("test.py")
        assert location.line_number == 42
        assert location.column_number == 10
        assert location.function_name == "test_function"
        assert location.url == "https://example.com/test"
        assert location.request_id == "req-123"
        assert location.timestamp == timestamp
    
    def test_file_path_validation(self):
        """Test file path validation and conversion."""
        # String path should be converted to Path
        location = IssueLocation(file_path="test.py")
        assert isinstance(location.file_path, Path)
        assert location.file_path == Path("test.py")
        
        # Path object should remain Path
        path_obj = Path("another.py")
        location = IssueLocation(file_path=path_obj)
        assert location.file_path is path_obj
    
    def test_line_number_validation(self):
        """Test line number validation."""
        # Valid line number
        location = IssueLocation(line_number=1)
        assert location.line_number == 1
        
        # Invalid line number (less than 1)
        with pytest.raises(ValueError):
            IssueLocation(line_number=0)
        
        with pytest.raises(ValueError):
            IssueLocation(line_number=-1)
    
    def test_column_number_validation(self):
        """Test column number validation."""
        # Valid column number
        location = IssueLocation(column_number=1)
        assert location.column_number == 1
        
        # Invalid column number (less than 1)
        with pytest.raises(ValueError):
            IssueLocation(column_number=0)
    
    def test_str_representation(self):
        """Test string representation of location."""
        # Empty location
        location = IssueLocation()
        assert str(location) == "Unknown location"
        
        # File path only
        location = IssueLocation(file_path=Path("test.py"))
        assert str(location) == "test.py"
        
        # File path and line number
        location = IssueLocation(file_path=Path("test.py"), line_number=42)
        assert str(location) == "test.py | line 42"
        
        # URL only
        location = IssueLocation(url="https://example.com")
        assert str(location) == "URL: https://example.com"
        
        # Multiple components
        location = IssueLocation(
            file_path=Path("test.py"),
            line_number=42,
            url="https://example.com"
        )
        assert str(location) == "test.py | line 42 | URL: https://example.com"


class TestIssueEvidence:
    """Test IssueEvidence model."""
    
    def test_evidence_creation(self):
        """Test creating evidence."""
        evidence = IssueEvidence(
            type="header",
            description="Suspicious header found",
            raw_data={"X-Debug": "true"},
            confidence=0.8,
            source="HTTP response",
            metadata={"parser": "http"}
        )
        
        assert evidence.type == "header"
        assert evidence.description == "Suspicious header found"
        assert evidence.raw_data == {"X-Debug": "true"}
        assert evidence.confidence == 0.8
        assert evidence.source == "HTTP response"
        assert evidence.metadata == {"parser": "http"}
    
    def test_confidence_validation(self):
        """Test confidence validation."""
        # Valid confidence values
        evidence = IssueEvidence(
            type="test", description="test", raw_data={}, confidence=0.0
        )
        assert evidence.confidence == 0.0
        
        evidence = IssueEvidence(
            type="test", description="test", raw_data={}, confidence=1.0
        )
        assert evidence.confidence == 1.0
        
        # Invalid confidence values
        with pytest.raises(ValueError):
            IssueEvidence(
                type="test", description="test", raw_data={}, confidence=-0.1
            )
        
        with pytest.raises(ValueError):
            IssueEvidence(
                type="test", description="test", raw_data={}, confidence=1.1
            )
    
    def test_confidence_level_property(self):
        """Test confidence level computed property."""
        evidence = IssueEvidence(
            type="test", description="test", raw_data={}, confidence=0.9
        )
        assert evidence.confidence_level == DetectionConfidence.VERY_HIGH
        
        evidence = IssueEvidence(
            type="test", description="test", raw_data={}, confidence=0.5
        )
        assert evidence.confidence_level == DetectionConfidence.MEDIUM
    
    def test_to_summary(self):
        """Test evidence summary generation."""
        evidence = IssueEvidence(
            type="header",
            description="Debug header detected",
            raw_data={},
            confidence=0.85
        )
        
        summary = evidence.to_summary()
        assert summary == "header: Debug header detected (confidence: 0.85)"


class TestIssueMetadata:
    """Test IssueMetadata model."""
    
    def test_metadata_creation_defaults(self):
        """Test creating metadata with defaults."""
        metadata = IssueMetadata()
        
        assert metadata.tags == []
        assert metadata.references == []
        assert metadata.affected_components == []
        assert metadata.detection_method is None
        assert metadata.false_positive_likelihood == 0.0
        assert metadata.business_impact is None
        assert metadata.technical_impact is None
        assert metadata.compliance_frameworks == []
        assert metadata.regulatory_requirements == []
        assert metadata.first_seen is None
        assert metadata.last_seen is None
        assert metadata.occurrence_count == 1
    
    def test_metadata_creation_full(self):
        """Test creating metadata with all fields."""
        first_seen = datetime.now(timezone.utc)
        last_seen = datetime.now(timezone.utc)
        
        metadata = IssueMetadata(
            tags=["security", "privacy"],
            references=["CVE-2023-1234", "https://example.com/advisory"],
            affected_components=["auth", "session"],
            detection_method="static_analysis",
            false_positive_likelihood=0.1,
            business_impact="High - customer data exposure",
            technical_impact="Authentication bypass possible",
            compliance_frameworks=["GDPR", "SOX"],
            regulatory_requirements=["PCI-DSS"],
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=5
        )
        
        assert metadata.tags == ["security", "privacy"]
        assert metadata.references == ["CVE-2023-1234", "https://example.com/advisory"]
        assert metadata.affected_components == ["auth", "session"]
        assert metadata.detection_method == "static_analysis"
        assert metadata.false_positive_likelihood == 0.1
        assert metadata.business_impact == "High - customer data exposure"
        assert metadata.technical_impact == "Authentication bypass possible"
        assert metadata.compliance_frameworks == ["GDPR", "SOX"]
        assert metadata.regulatory_requirements == ["PCI-DSS"]
        assert metadata.first_seen == first_seen
        assert metadata.last_seen == last_seen
        assert metadata.occurrence_count == 5
    
    def test_false_positive_likelihood_validation(self):
        """Test false positive likelihood validation."""
        # Valid values
        metadata = IssueMetadata(false_positive_likelihood=0.0)
        assert metadata.false_positive_likelihood == 0.0
        
        metadata = IssueMetadata(false_positive_likelihood=1.0)
        assert metadata.false_positive_likelihood == 1.0
        
        # Invalid values
        with pytest.raises(ValueError):
            IssueMetadata(false_positive_likelihood=-0.1)
        
        with pytest.raises(ValueError):
            IssueMetadata(false_positive_likelihood=1.1)
    
    def test_occurrence_count_validation(self):
        """Test occurrence count validation."""
        # Valid count
        metadata = IssueMetadata(occurrence_count=1)
        assert metadata.occurrence_count == 1
        
        # Invalid count
        with pytest.raises(ValueError):
            IssueMetadata(occurrence_count=0)


class TestRemediationSuggestion:
    """Test RemediationSuggestion model."""
    
    def test_suggestion_creation_minimal(self):
        """Test creating suggestion with minimal data."""
        suggestion = RemediationSuggestion(
            title="Fix the issue",
            description="Apply the recommended fix"
        )
        
        assert suggestion.title == "Fix the issue"
        assert suggestion.description == "Apply the recommended fix"
        assert suggestion.priority == 1
        assert suggestion.effort_level == "medium"
        assert suggestion.risk_level == "low"
        assert UUID(suggestion.id)  # Should be valid UUID
    
    def test_suggestion_creation_full(self):
        """Test creating suggestion with all data."""
        suggestion = RemediationSuggestion(
            title="Update authentication",
            description="Implement proper session management",
            priority=2,
            effort_level="high",
            code_fix="session.regenerate_id()",
            configuration_changes=["session.timeout = 3600"],
            dependencies=["php-session"],
            validation_steps=["Test login", "Test logout"],
            test_cases=["test_session_timeout"],
            risk_level="medium",
            side_effects=["Users may need to re-login"],
            rollback_plan="Revert to previous session config"
        )
        
        assert suggestion.title == "Update authentication"
        assert suggestion.description == "Implement proper session management"
        assert suggestion.priority == 2
        assert suggestion.effort_level == "high"
        assert suggestion.code_fix == "session.regenerate_id()"
        assert suggestion.configuration_changes == ["session.timeout = 3600"]
        assert suggestion.dependencies == ["php-session"]
        assert suggestion.validation_steps == ["Test login", "Test logout"]
        assert suggestion.test_cases == ["test_session_timeout"]
        assert suggestion.risk_level == "medium"
        assert suggestion.side_effects == ["Users may need to re-login"]
        assert suggestion.rollback_plan == "Revert to previous session config"
    
    def test_priority_validation(self):
        """Test priority validation."""
        # Valid priorities
        for priority in [1, 2, 3, 4, 5]:
            suggestion = RemediationSuggestion(
                title="Test", description="Test", priority=priority
            )
            assert suggestion.priority == priority
        
        # Invalid priorities
        with pytest.raises(ValueError):
            RemediationSuggestion(title="Test", description="Test", priority=0)
        
        with pytest.raises(ValueError):
            RemediationSuggestion(title="Test", description="Test", priority=6)
    
    def test_effort_level_validation(self):
        """Test effort level validation."""
        # Valid effort levels
        for level in ["low", "medium", "high"]:
            suggestion = RemediationSuggestion(
                title="Test", description="Test", effort_level=level
            )
            assert suggestion.effort_level == level
        
        # Invalid effort level
        with pytest.raises(ValueError):
            RemediationSuggestion(
                title="Test", description="Test", effort_level="invalid"
            )
    
    def test_risk_level_validation(self):
        """Test risk level validation."""
        # Valid risk levels
        for level in ["low", "medium", "high", "critical"]:
            suggestion = RemediationSuggestion(
                title="Test", description="Test", risk_level=level
            )
            assert suggestion.risk_level == level
        
        # Invalid risk level
        with pytest.raises(ValueError):
            RemediationSuggestion(
                title="Test", description="Test", risk_level="invalid"
            )


class TestIssue:
    """Test Issue model."""
    
    def test_issue_creation_minimal(self):
        """Test creating issue with minimal required data."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Authentication bypass",
            description="Authentication can be bypassed",
            confidence=0.9,
            impact_score=80
        )
        
        assert issue.category == IssueCategory.AUTHENTICATION
        assert issue.severity == SeverityLevel.HIGH
        assert issue.title == "Authentication bypass"
        assert issue.description == "Authentication can be bypassed"
        assert issue.confidence == 0.9
        assert issue.impact_score == 80
        assert issue.exploitability_score == 0
        assert issue.status == "open"
        assert UUID(issue.id)  # Should be valid UUID
        assert isinstance(issue.detection_timestamp, datetime)
        assert isinstance(issue.metadata, IssueMetadata)
    
    def test_issue_creation_full(self):
        """Test creating issue with all data."""
        location = IssueLocation(file_path=Path("test.py"), line_number=42)
        evidence = IssueEvidence(
            type="code", description="Vulnerable code", raw_data={}, confidence=0.8
        )
        metadata = IssueMetadata(tags=["security"])
        suggestion = RemediationSuggestion(
            title="Fix auth", description="Update authentication"
        )
        timestamp = datetime.now(timezone.utc)
        
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.CRITICAL,
            title="Critical auth issue",
            description="Critical authentication vulnerability",
            summary="Auth bypass possible",
            confidence=0.95,
            detection_timestamp=timestamp,
            location=location,
            evidence=[evidence],
            metadata=metadata,
            impact_score=95,
            exploitability_score=85,
            remediation_suggestions=[suggestion],
            status="investigating",
            assigned_to="security-team",
            resolution_notes="Under investigation",
            raw_data={"source": "scanner"}
        )
        
        assert issue.category == IssueCategory.AUTHENTICATION
        assert issue.severity == SeverityLevel.CRITICAL
        assert issue.title == "Critical auth issue"
        assert issue.description == "Critical authentication vulnerability"
        assert issue.summary == "Auth bypass possible"
        assert issue.confidence == 0.95
        assert issue.detection_timestamp == timestamp
        assert issue.location == location
        assert issue.evidence == [evidence]
        assert issue.metadata == metadata
        assert issue.impact_score == 95
        assert issue.exploitability_score == 85
        assert issue.remediation_suggestions == [suggestion]
        assert issue.status == "investigating"
        assert issue.assigned_to == "security-team"
        assert issue.resolution_notes == "Under investigation"
        assert issue.raw_data == {"source": "scanner"}
    
    def test_confidence_validation(self):
        """Test confidence validation."""
        # Valid confidence values
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.0,
            impact_score=50
        )
        assert issue.confidence == 0.0
        
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=1.0,
            impact_score=50
        )
        assert issue.confidence == 1.0
        
        # Invalid confidence values
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=-0.1,
                impact_score=50
            )
        
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=1.1,
                impact_score=50
            )
    
    def test_impact_score_validation(self):
        """Test impact score validation."""
        # Valid scores
        for score in [0, 50, 100]:
            issue = Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=score
            )
            assert issue.impact_score == score
        
        # Invalid scores
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=-1
            )
        
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=101
            )
    
    def test_exploitability_score_validation(self):
        """Test exploitability score validation."""
        # Valid scores
        for score in [0, 50, 100]:
            issue = Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=50,
                exploitability_score=score
            )
            assert issue.exploitability_score == score
        
        # Invalid scores
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=50,
                exploitability_score=-1
            )
        
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=50,
                exploitability_score=101
            )
    
    def test_status_validation(self):
        """Test status validation."""
        # Valid statuses
        valid_statuses = ['open', 'investigating', 'resolved', 'false_positive', 'wont_fix']
        for status in valid_statuses:
            issue = Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=50,
                status=status
            )
            assert issue.status == status
        
        # Invalid status
        with pytest.raises(ValueError):
            Issue(
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Test",
                confidence=0.8,
                impact_score=50,
                status="invalid_status"
            )
    
    def test_confidence_level_property(self):
        """Test confidence level computed property."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.9,
            impact_score=50
        )
        assert issue.confidence_level == DetectionConfidence.VERY_HIGH
    
    def test_risk_score_property(self):
        """Test risk score computed property."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.8,
            impact_score=80,
            exploitability_score=60
        )
        
        # Risk score = (impact * 0.4 + exploitability * 0.3) / 100 + confidence * 0.3
        expected = (80 * 0.4 + 60 * 0.3) / 100.0 + 0.8 * 0.3
        assert abs(issue.risk_score - expected) < 0.001
        
        # Risk score should be capped at 1.0
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=1.0,
            impact_score=100,
            exploitability_score=100
        )
        assert issue.risk_score <= 1.0
    
    def test_display_title_property(self):
        """Test display title computed property."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Login bypass",
            description="Test",
            confidence=0.8,
            impact_score=50
        )
        
        # Should include category in display title
        display_title = issue.display_title
        assert "Authentication" in display_title
        assert "Login bypass" in display_title
    
    def test_add_evidence(self):
        """Test adding evidence to issue."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.5,
            impact_score=50
        )
        
        evidence = IssueEvidence(
            type="code", description="Vulnerable code", raw_data={}, confidence=0.9
        )
        
        issue.add_evidence(evidence)
        
        assert len(issue.evidence) == 1
        assert issue.evidence[0] == evidence
        # Confidence should be updated based on evidence
        assert issue.confidence >= 0.5  # Should be at least original confidence
    
    def test_add_remediation(self):
        """Test adding remediation suggestion."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.8,
            impact_score=50
        )
        
        suggestion1 = RemediationSuggestion(
            title="Fix 1", description="First fix", priority=2
        )
        suggestion2 = RemediationSuggestion(
            title="Fix 2", description="Second fix", priority=1
        )
        
        issue.add_remediation(suggestion1)
        issue.add_remediation(suggestion2)
        
        assert len(issue.remediation_suggestions) == 2
        # Should be sorted by priority (1 comes before 2)
        assert issue.remediation_suggestions[0].priority == 1
        assert issue.remediation_suggestions[1].priority == 2
    
    def test_get_evidence_by_type(self):
        """Test getting evidence by type."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.8,
            impact_score=50
        )
        
        evidence1 = IssueEvidence(
            type="code", description="Code evidence", raw_data={}, confidence=0.8
        )
        evidence2 = IssueEvidence(
            type="header", description="Header evidence", raw_data={}, confidence=0.7
        )
        evidence3 = IssueEvidence(
            type="code", description="More code evidence", raw_data={}, confidence=0.9
        )
        
        issue.add_evidence(evidence1)
        issue.add_evidence(evidence2)
        issue.add_evidence(evidence3)
        
        code_evidence = issue.get_evidence_by_type("code")
        assert len(code_evidence) == 2
        assert evidence1 in code_evidence
        assert evidence3 in code_evidence
        
        header_evidence = issue.get_evidence_by_type("header")
        assert len(header_evidence) == 1
        assert evidence2 in header_evidence
        
        missing_evidence = issue.get_evidence_by_type("nonexistent")
        assert len(missing_evidence) == 0
    
    def test_get_primary_remediation(self):
        """Test getting primary remediation suggestion."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test",
            description="Test",
            confidence=0.8,
            impact_score=50
        )
        
        # No remediation suggestions
        assert issue.get_primary_remediation() is None
        
        # Add suggestions with different priorities
        suggestion1 = RemediationSuggestion(
            title="Fix 1", description="First fix", priority=3
        )
        suggestion2 = RemediationSuggestion(
            title="Fix 2", description="Second fix", priority=1
        )
        suggestion3 = RemediationSuggestion(
            title="Fix 3", description="Third fix", priority=2
        )
        
        issue.add_remediation(suggestion1)
        issue.add_remediation(suggestion2)
        issue.add_remediation(suggestion3)
        
        primary = issue.get_primary_remediation()
        assert primary is not None
        assert primary.priority == 1
        assert primary.title == "Fix 2"
    
    def test_to_dict(self):
        """Test converting issue to dictionary."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test issue",
            description="Test description",
            confidence=0.8,
            impact_score=75
        )
        
        issue_dict = issue.to_dict()
        
        assert isinstance(issue_dict, dict)
        assert issue_dict['title'] == "Test issue"
        assert issue_dict['description'] == "Test description"
        assert issue_dict['confidence'] == 0.8
        assert issue_dict['impact_score'] == 75
        # Should exclude None values
        assert 'summary' not in issue_dict or issue_dict['summary'] is None
    
    def test_to_summary_dict(self):
        """Test converting issue to summary dictionary."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Test issue",
            description="Test description",
            confidence=0.8,
            impact_score=75,
            raw_data={"sensitive": "data"}
        )
        
        evidence1 = IssueEvidence(
            type="code", description="Code evidence", raw_data={}, confidence=0.8
        )
        evidence2 = IssueEvidence(
            type="header", description="Header evidence", raw_data={}, confidence=0.7
        )
        
        issue.add_evidence(evidence1)
        issue.add_evidence(evidence2)
        
        summary_dict = issue.to_summary_dict()
        
        assert isinstance(summary_dict, dict)
        assert summary_dict['title'] == "Test issue"
        # Should exclude raw_data and evidence
        assert 'raw_data' not in summary_dict
        assert 'evidence' not in summary_dict
        # Should include evidence summary
        assert summary_dict['evidence_count'] == 2
        assert set(summary_dict['evidence_types']) == {'code', 'header'}
    
    def test_str_representation(self):
        """Test string representation of issue."""
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Login bypass",
            description="Authentication can be bypassed",
            confidence=0.85,
            impact_score=80
        )
        
        str_repr = str(issue)
        assert "HIGH" in str_repr
        assert "Login bypass" in str_repr
        assert "0.85" in str_repr


class TestDetectionRule:
    """Test DetectionRule model."""
    
    def test_rule_creation_minimal(self):
        """Test creating rule with minimal data."""
        rule = DetectionRule(
            id="rule-001",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="password.*=.*['\"].*['\"]",
            description="Detects hardcoded passwords"
        )
        
        assert rule.id == "rule-001"
        assert rule.name == "Test Rule"
        assert rule.version == "1.0.0"
        assert rule.category == IssueCategory.AUTHENTICATION
        assert rule.severity == SeverityLevel.HIGH
        assert rule.pattern == "password.*=.*['\"].*['\"]"
        assert rule.pattern_type == "regex"
        assert rule.case_sensitive is True
        assert rule.description == "Detects hardcoded passwords"
        assert rule.enabled is True
        assert rule.confidence == 0.8
        assert rule.timeout_ms == 5000
        assert rule.priority == 50
    
    def test_rule_creation_full(self):
        """Test creating rule with all data."""
        created_at = datetime.now(timezone.utc)
        updated_at = datetime.now(timezone.utc)
        
        rule = DetectionRule(
            id="rule-002",
            name="Advanced Rule",
            version="2.1.0",
            category=IssueCategory.DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
            tags=["security", "data"],
            pattern="SELECT.*FROM.*users",
            pattern_type="regex",
            case_sensitive=False,
            conditions=["context.get('sql') is not None"],
            exclude_patterns=["-- safe comment"],
            description="Detects SQL injection",
            rationale="SQL injection can lead to data breach",
            references=["OWASP-A03", "CWE-89"],
            enabled=True,
            confidence=DetectionConfidence.HIGH,
            max_matches=10,
            default_remediation="Use parameterized queries",
            code_fix_template="Use prepared statements",
            timeout_ms=3000,
            priority=90,
            author="security-team",
            created_at=created_at,
            updated_at=updated_at
        )
        
        assert rule.id == "rule-002"
        assert rule.name == "Advanced Rule"
        assert rule.version == "2.1.0"
        assert rule.category == IssueCategory.DATA_LEAKAGE
        assert rule.severity == SeverityLevel.CRITICAL
        assert rule.tags == ["security", "data"]
        assert rule.pattern == "SELECT.*FROM.*users"
        assert rule.pattern_type == "regex"
        assert rule.case_sensitive is False
        assert rule.conditions == ["context.get('sql') is not None"]
        assert rule.exclude_patterns == ["-- safe comment"]
        assert rule.description == "Detects SQL injection"
        assert rule.rationale == "SQL injection can lead to data breach"
        assert rule.references == ["OWASP-A03", "CWE-89"]
        assert rule.enabled is True
        assert rule.confidence == DetectionConfidence.HIGH.numeric_value
        assert rule.max_matches == 10
        assert rule.default_remediation == "Use parameterized queries"
        assert rule.code_fix_template == "Use prepared statements"
        assert rule.timeout_ms == 3000
        assert rule.priority == 90
        assert rule.author == "security-team"
        assert rule.created_at == created_at
        assert rule.updated_at == updated_at
    
    def test_confidence_validation_float(self):
        """Test confidence validation with float values."""
        # Valid float confidence
        rule = DetectionRule(
            id="rule-003",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            confidence=0.75
        )
        assert rule.confidence == 0.75
        
        # Invalid float confidence
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-004",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                confidence=1.5
            )
    
    def test_confidence_validation_enum(self):
        """Test confidence validation with DetectionConfidence enum."""
        rule = DetectionRule(
            id="rule-005",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            confidence=DetectionConfidence.MEDIUM
        )
        assert rule.confidence == DetectionConfidence.MEDIUM.numeric_value
    
    def test_confidence_validation_string(self):
        """Test confidence validation with string values."""
        # Valid string that converts to enum
        rule = DetectionRule(
            id="rule-006",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            confidence="high"
        )
        assert rule.confidence == DetectionConfidence.HIGH.numeric_value
        
        # Valid string that converts to float
        rule = DetectionRule(
            id="rule-007",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            confidence="0.6"
        )
        assert rule.confidence == 0.6
        
        # Invalid string
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-008",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                confidence="invalid"
            )
    
    def test_pattern_type_validation(self):
        """Test pattern type validation."""
        # Valid pattern types
        valid_types = ['regex', 'string', 'xpath', 'jsonpath', 'custom']
        for pattern_type in valid_types:
            rule = DetectionRule(
                id=f"rule-{pattern_type}",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                pattern_type=pattern_type,
                description="Test"
            )
            assert rule.pattern_type == pattern_type
        
        # Invalid pattern type
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-invalid",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                pattern_type="invalid_type",
                description="Test"
            )
    
    def test_timeout_validation(self):
        """Test timeout validation."""
        # Valid timeout
        rule = DetectionRule(
            id="rule-timeout",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            timeout_ms=1000
        )
        assert rule.timeout_ms == 1000
        
        # Invalid timeout (too low)
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-timeout-low",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                timeout_ms=50
            )
    
    def test_priority_validation(self):
        """Test priority validation."""
        # Valid priorities
        for priority in [1, 50, 100]:
            rule = DetectionRule(
                id=f"rule-priority-{priority}",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                priority=priority
            )
            assert rule.priority == priority
        
        # Invalid priorities
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-priority-low",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                priority=0
            )
        
        with pytest.raises(ValueError):
            DetectionRule(
                id="rule-priority-high",
                name="Test Rule",
                category=IssueCategory.AUTHENTICATION,
                severity=SeverityLevel.HIGH,
                pattern="test",
                description="Test",
                priority=101
            )
    
    def test_matches_context(self):
        """Test context matching logic."""
        rule = DetectionRule(
            id="rule-context",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test",
            description="Test",
            conditions=["context.get('type') == 'sql'"],
            exclude_patterns=["safe_pattern"]
        )
        
        # Context matches conditions
        context = {"type": "sql", "content": "SELECT * FROM users"}
        assert rule.matches_context(context) is True
        
        # Context doesn't match conditions
        context = {"type": "html", "content": "SELECT * FROM users"}
        assert rule.matches_context(context) is False
        
        # Context matches exclude pattern
        context = {"type": "sql", "content": "safe_pattern in content"}
        assert rule.matches_context(context) is False
    
    def test_create_issue_template(self):
        """Test creating issue template from rule."""
        rule = DetectionRule(
            id="rule-template",
            name="Password Detection",
            version="1.2.0",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="password.*=.*['\"].*['\"]",
            description="Detects hardcoded passwords",
            confidence=0.85,
            tags=["security", "credentials"]
        )
        
        template = rule.create_issue_template()
        
        assert template['category'] == IssueCategory.AUTHENTICATION
        assert template['severity'] == SeverityLevel.HIGH
        assert template['title'] == "Password Detection detected"
        assert template['description'] == "Detects hardcoded passwords"
        assert template['confidence'] == 0.85
        assert template['metadata']['detection_method'] == "Rule: rule-template"
        assert template['metadata']['rule_version'] == "1.2.0"
        assert template['metadata']['tags'] == ["security", "credentials"]
    
    def test_to_dict(self):
        """Test converting rule to dictionary."""
        rule = DetectionRule(
            id="rule-dict",
            name="Test Rule",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern="test.*pattern",
            description="Test rule for dictionary conversion",
            confidence=0.9,
            tags=["test"]
        )
        
        rule_dict = rule.to_dict()
        
        assert isinstance(rule_dict, dict)
        assert rule_dict['id'] == "rule-dict"
        assert rule_dict['name'] == "Test Rule"
        assert rule_dict['pattern'] == "test.*pattern"
        assert rule_dict['description'] == "Test rule for dictionary conversion"
        assert rule_dict['confidence'] == 0.9
        assert rule_dict['tags'] == ["test"]
        # Should exclude None values
        assert 'rationale' not in rule_dict or rule_dict['rationale'] is None


class TestIssueIntegration:
    """Integration tests for issue models working together."""
    
    def test_complete_issue_workflow(self):
        """Test complete workflow of creating and managing an issue."""
        # Create location
        location = IssueLocation(
            file_path=Path("vulnerable.py"),
            line_number=42,
            function_name="authenticate"
        )
        
        # Create evidence
        evidence1 = IssueEvidence(
            type="code",
            description="Hardcoded password found",
            raw_data={"line": "password = 'admin123'"},
            confidence=0.9
        )
        
        evidence2 = IssueEvidence(
            type="pattern",
            description="Password pattern match",
            raw_data={"pattern": "password.*=.*['\"].*['\"]"},
            confidence=0.8
        )
        
        # Create remediation suggestion
        remediation = RemediationSuggestion(
            title="Remove hardcoded password",
            description="Use environment variables or secure configuration",
            priority=1,
            effort_level="low",
            code_fix="password = os.getenv('DB_PASSWORD')",
            validation_steps=["Test with environment variable", "Verify no hardcoded secrets"]
        )
        
        # Create issue
        issue = Issue(
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            title="Hardcoded password detected",
            description="Password is hardcoded in source code",
            confidence=0.7,  # Will be updated when evidence is added
            impact_score=85,
            exploitability_score=70,
            location=location
        )
        
        # Add evidence and remediation
        issue.add_evidence(evidence1)
        issue.add_evidence(evidence2)
        issue.add_remediation(remediation)
        
        # Verify the complete issue
        assert issue.location == location
        assert len(issue.evidence) == 2
        assert len(issue.remediation_suggestions) == 1
        assert issue.confidence >= 0.7  # Should be updated based on evidence
        
        # Test evidence retrieval
        code_evidence = issue.get_evidence_by_type("code")
        assert len(code_evidence) == 1
        assert code_evidence[0] == evidence1
        
        # Test primary remediation
        primary = issue.get_primary_remediation()
        assert primary == remediation
        
        # Test risk score calculation
        assert 0.0 <= issue.risk_score <= 1.0
        
        # Test serialization
        issue_dict = issue.to_dict()
        assert isinstance(issue_dict, dict)
        assert 'evidence' in issue_dict
        assert len(issue_dict['evidence']) == 2
        
        summary_dict = issue.to_summary_dict()
        assert 'evidence_count' in summary_dict
        assert summary_dict['evidence_count'] == 2
        assert 'evidence_types' in summary_dict
        assert set(summary_dict['evidence_types']) == {'code', 'pattern'}
    
    def test_detection_rule_to_issue_conversion(self):
        """Test converting detection rule to issue template."""
        rule = DetectionRule(
            id="hardcoded-password",
            name="Hardcoded Password Detection",
            version="1.0.0",
            category=IssueCategory.AUTHENTICATION,
            severity=SeverityLevel.HIGH,
            pattern=r"password\s*=\s*['\"][^'\"]+['\"]",
            description="Detects hardcoded passwords in source code",
            confidence=0.85,
            tags=["security", "credentials", "authentication"]
        )
        
        # Create issue from rule template
        template = rule.create_issue_template()
        
        issue = Issue(
            **template,
            impact_score=80,
            location=IssueLocation(
                file_path=Path("auth.py"),
                line_number=15
            )
        )
        
        # Verify issue was created correctly from rule
        assert issue.category == rule.category
        assert issue.severity == rule.severity
        assert issue.confidence == rule.confidence
        assert issue.metadata.detection_method == f"Rule: {rule.id}"
        assert issue.metadata.tags == rule.tags
        
        # Test display title includes category
        assert "Authentication" in issue.display_title
        assert rule.name in issue.display_title
