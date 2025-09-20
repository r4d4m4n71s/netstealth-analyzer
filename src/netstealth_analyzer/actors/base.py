"""
Base classes and interfaces for the Network Actor Detection System.

This module defines the core abstractions for network actor identification,
pattern matching, and behavioral analysis.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

import re
import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union, Pattern
from enum import Enum, auto

from pydantic import BaseModel, Field, field_validator

from ..models.enums import RiskLevel, DetectionConfidence
from ..models.network import NetworkTrace, NetworkHop
from ..compatibility import override


class ActorCategory(Enum):
    """Categories of network actors."""
    CLIENT = "client"
    PROXY = "proxy"
    VPN = "vpn"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    SECURITY_SERVICE = "security_service"
    SERVER = "server"
    UNKNOWN = "unknown"


class AnonymityLevel(Enum):
    """Levels of anonymity provided by network actors."""
    TRANSPARENT = "transparent"  # Actor reveals client information
    ANONYMOUS = "anonymous"      # Actor hides some client information
    ELITE = "elite"             # Actor provides maximum anonymity
    UNKNOWN = "unknown"         # Anonymity level cannot be determined


@dataclass
class ActorIdentification:
    """
    Result of network actor identification.
    
    Contains information about an identified network actor including
    confidence level, patterns matched, and metadata.
    """
    
    actor_type: str
    actor_category: ActorCategory
    confidence: float
    patterns_matched: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate confidence score."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
    
    @property
    def confidence_level(self) -> DetectionConfidence:
        """Get confidence level enum."""
        return DetectionConfidence.from_score(self.confidence)
    
    def is_high_confidence(self) -> bool:
        """Check if identification has high confidence."""
        return self.confidence >= 0.8


@dataclass
class BehaviorAnalysis:
    """
    Analysis of network actor behavior and characteristics.
    
    Contains risk assessment, performance impact, and other behavioral
    characteristics of the identified network actor.
    """
    
    risk_level: RiskLevel
    risk_score: float
    anonymity_level: AnonymityLevel
    detection_likelihood: float
    performance_impact: str
    characteristics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate scores."""
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
        if not 0.0 <= self.detection_likelihood <= 1.0:
            raise ValueError("Detection likelihood must be between 0.0 and 1.0")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get behavior analysis summary."""
        return {
            'risk_level': self.risk_level.value,
            'risk_score': self.risk_score,
            'anonymity_level': self.anonymity_level.value,
            'detection_likelihood': self.detection_likelihood,
            'performance_impact': self.performance_impact,
            'characteristics_count': len(self.characteristics),
            'recommendations_count': len(self.recommendations)
        }


class ActorPattern(ABC):
    """
    Base class for network actor detection patterns.
    
    Patterns are used to identify network actors based on various
    indicators such as headers, IP ranges, response content, etc.
    """
    
    def __init__(
        self, 
        confidence: float = 0.5, 
        required: bool = False,
        description: str = ""
    ):
        """
        Initialize pattern.
        
        Args:
            confidence: Confidence score if pattern matches (0.0-1.0)
            required: Whether this pattern is required for identification
            description: Human-readable description of the pattern
        """
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        self.confidence = confidence
        self.required = required
        self.description = description
    
    @abstractmethod
    def matches(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> bool:
        """
        Check if pattern matches the given trace/hop.
        
        Args:
            trace: Network trace to check
            hop: Optional specific hop to check
            
        Returns:
            True if pattern matches, False otherwise
        """
        pass
    
    def get_match_info(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Dict[str, Any]:
        """
        Get detailed information about the pattern match.
        
        Args:
            trace: Network trace that was checked
            hop: Optional specific hop that was checked
            
        Returns:
            Dictionary with match information
        """
        return {
            'pattern_type': self.__class__.__name__,
            'confidence': self.confidence,
            'required': self.required,
            'description': self.description,
            'matches': self.matches(trace, hop)
        }


class HeaderPattern(ActorPattern):
    """Pattern that matches HTTP headers."""
    
    def __init__(
        self,
        header_name: str,
        value_pattern: Optional[str] = None,
        case_sensitive: bool = False,
        **kwargs
    ):
        """
        Initialize header pattern.
        
        Args:
            header_name: Name of the header to match
            value_pattern: Optional regex pattern for header value
            case_sensitive: Whether matching is case sensitive
            **kwargs: Additional pattern arguments
        """
        super().__init__(**kwargs)
        self.header_name = header_name.lower() if not case_sensitive else header_name
        self.value_pattern = re.compile(value_pattern, re.IGNORECASE if not case_sensitive else 0) if value_pattern else None
        self.case_sensitive = case_sensitive
    
    @override
    def matches(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> bool:
        """Check if header pattern matches."""
        # Get HTTP data from trace
        if not trace.is_http() or not trace.http_data:
            return False
        
        request = trace.http_data.request
        if not request or not request.headers:
            return False
        
        # Check headers
        for header in request.headers:
            header_name = header.get('name', '')
            if not self.case_sensitive:
                header_name = header_name.lower()
            
            if header_name == self.header_name:
                if self.value_pattern:
                    header_value = header.get('value', '')
                    return bool(self.value_pattern.search(header_value))
                return True
        
        return False
    
    @override
    def get_match_info(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Dict[str, Any]:
        """Get header pattern match information."""
        info = super().get_match_info(trace, hop)
        info.update({
            'header_name': self.header_name,
            'value_pattern': self.value_pattern.pattern if self.value_pattern else None,
            'case_sensitive': self.case_sensitive
        })
        return info


class IPRangePattern(ActorPattern):
    """Pattern that matches IP address ranges."""
    
    def __init__(
        self,
        ip_ranges: List[str],
        check_source: bool = True,
        check_destination: bool = True,
        **kwargs
    ):
        """
        Initialize IP range pattern.
        
        Args:
            ip_ranges: List of IP ranges in CIDR notation
            check_source: Whether to check source IP
            check_destination: Whether to check destination IP
            **kwargs: Additional pattern arguments
        """
        super().__init__(**kwargs)
        self.ip_networks = []
        
        for ip_range in ip_ranges:
            try:
                self.ip_networks.append(ipaddress.ip_network(ip_range, strict=False))
            except ValueError as e:
                raise ValueError(f"Invalid IP range '{ip_range}': {e}")
        
        self.check_source = check_source
        self.check_destination = check_destination
    
    @override
    def matches(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> bool:
        """Check if IP range pattern matches."""
        ips_to_check = []
        
        # Check hop IPs if provided
        if hop:
            if self.check_source:
                ips_to_check.append(hop.incoming_ip)
            if self.check_destination:
                ips_to_check.append(hop.outgoing_ip)
        else:
            # Check all hops in trace
            for trace_hop in trace.hops:
                if self.check_source:
                    ips_to_check.append(trace_hop.incoming_ip)
                if self.check_destination:
                    ips_to_check.append(trace_hop.outgoing_ip)
        
        # Check if any IP matches any range
        for ip_str in ips_to_check:
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for network in self.ip_networks:
                    if ip_addr in network:
                        return True
            except ValueError:
                continue  # Skip invalid IP addresses
        
        return False
    
    @override
    def get_match_info(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Dict[str, Any]:
        """Get IP range pattern match information."""
        info = super().get_match_info(trace, hop)
        info.update({
            'ip_ranges': [str(network) for network in self.ip_networks],
            'check_source': self.check_source,
            'check_destination': self.check_destination
        })
        return info


class ResponsePattern(ActorPattern):
    """Pattern that matches response content."""
    
    def __init__(
        self,
        pattern: str,
        case_sensitive: bool = False,
        **kwargs
    ):
        """
        Initialize response pattern.
        
        Args:
            pattern: Regex pattern to match in response content
            case_sensitive: Whether matching is case sensitive
            **kwargs: Additional pattern arguments
        """
        super().__init__(**kwargs)
        flags = 0 if case_sensitive else re.IGNORECASE
        self.pattern = re.compile(pattern, flags)
        self.case_sensitive = case_sensitive
    
    @override
    def matches(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> bool:
        """Check if response pattern matches."""
        # Get HTTP data from trace
        if not trace.is_http() or not trace.http_data:
            return False
        
        response = trace.http_data.response
        if not response or not response.body:
            return False
        
        return bool(self.pattern.search(str(response.body)))
    
    @override
    def get_match_info(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Dict[str, Any]:
        """Get response pattern match information."""
        info = super().get_match_info(trace, hop)
        info.update({
            'pattern': self.pattern.pattern,
            'case_sensitive': self.case_sensitive
        })
        return info


class PortPattern(ActorPattern):
    """Pattern that matches specific ports."""
    
    def __init__(
        self,
        ports: List[int],
        check_source: bool = False,
        check_destination: bool = True,
        **kwargs
    ):
        """
        Initialize port pattern.
        
        Args:
            ports: List of ports to match
            check_source: Whether to check source port
            check_destination: Whether to check destination port
            **kwargs: Additional pattern arguments
        """
        super().__init__(**kwargs)
        self.ports = set(ports)
        self.check_source = check_source
        self.check_destination = check_destination
    
    @override
    def matches(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> bool:
        """Check if port pattern matches."""
        ports_to_check = []
        
        # Check hop ports if provided
        if hop and hop.connection_info:
            if self.check_source:
                ports_to_check.append(hop.connection_info.source_port)
            if self.check_destination:
                ports_to_check.append(hop.connection_info.destination_port)
        else:
            # Check all hops in trace
            for trace_hop in trace.hops:
                if trace_hop.connection_info:
                    if self.check_source:
                        ports_to_check.append(trace_hop.connection_info.source_port)
                    if self.check_destination:
                        ports_to_check.append(trace_hop.connection_info.destination_port)
        
        # Check if any port matches
        return any(port in self.ports for port in ports_to_check)
    
    @override
    def get_match_info(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Dict[str, Any]:
        """Get port pattern match information."""
        info = super().get_match_info(trace, hop)
        info.update({
            'ports': list(self.ports),
            'check_source': self.check_source,
            'check_destination': self.check_destination
        })
        return info


class NetworkActor(ABC):
    """
    Base class for all network actors.
    
    Network actors represent entities in the network path that can be
    identified and analyzed for their behavior and characteristics.
    """
    
    def __init__(self):
        """Initialize network actor."""
        self._patterns: List[ActorPattern] = []
        self._compiled_patterns = False
    
    @property
    @abstractmethod
    def actor_type(self) -> str:
        """Get the actor type identifier."""
        pass
    
    @property
    @abstractmethod
    def actor_category(self) -> ActorCategory:
        """Get the actor category."""
        pass
    
    @property
    @abstractmethod
    def patterns(self) -> List[ActorPattern]:
        """Get detection patterns for this actor."""
        pass
    
    def _ensure_patterns_compiled(self) -> None:
        """Ensure patterns are compiled and ready for use."""
        if not self._compiled_patterns:
            self._patterns = self.patterns
            self._compiled_patterns = True
    
    def identify(self, trace: NetworkTrace, hop: Optional[NetworkHop] = None) -> Optional[ActorIdentification]:
        """
        Identify if this actor is present in the trace/hop.
        
        Args:
            trace: Network trace to analyze
            hop: Optional specific hop to analyze
            
        Returns:
            ActorIdentification if actor is identified, None otherwise
        """
        self._ensure_patterns_compiled()
        
        matched_patterns = []
        total_confidence = 0.0
        required_patterns_matched = 0
        required_patterns_total = 0
        
        for pattern in self._patterns:
            if pattern.required:
                required_patterns_total += 1
            
            if pattern.matches(trace, hop):
                matched_patterns.append(pattern.description or pattern.__class__.__name__)
                total_confidence += pattern.confidence
                
                if pattern.required:
                    required_patterns_matched += 1
        
        # Check if all required patterns are matched
        if required_patterns_total > 0 and required_patterns_matched < required_patterns_total:
            return None
        
        # Calculate overall confidence
        if not matched_patterns:
            return None
        
        # Average confidence of matched patterns, with bonus for multiple matches
        base_confidence = total_confidence / len(matched_patterns)
        match_bonus = min(0.2, (len(matched_patterns) - 1) * 0.05)
        final_confidence = min(1.0, base_confidence + match_bonus)
        
        return ActorIdentification(
            actor_type=self.actor_type,
            actor_category=self.actor_category,
            confidence=final_confidence,
            patterns_matched=matched_patterns,
            metadata={
                'patterns_total': len(self._patterns),
                'patterns_matched': len(matched_patterns),
                'required_patterns_matched': required_patterns_matched,
                'required_patterns_total': required_patterns_total
            }
        )
    
    @abstractmethod
    def analyze_behavior(self, trace: NetworkTrace, identification: ActorIdentification) -> BehaviorAnalysis:
        """
        Analyze the behavior of this actor in the given trace.
        
        Args:
            trace: Network trace containing the actor
            identification: Actor identification result
            
        Returns:
            BehaviorAnalysis with risk assessment and characteristics
        """
        pass
    
    def get_actor_info(self) -> Dict[str, Any]:
        """Get information about this actor."""
        self._ensure_patterns_compiled()
        
        return {
            'actor_type': self.actor_type,
            'actor_category': self.actor_category.value,
            'patterns_count': len(self._patterns),
            'required_patterns': sum(1 for p in self._patterns if p.required),
            'description': self.__doc__ or f"{self.actor_type} network actor"
        }
    
    def __str__(self) -> str:
        """String representation of the actor."""
        return f"{self.__class__.__name__}(type={self.actor_type}, category={self.actor_category.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the actor."""
        return f"{self.__class__.__name__}(type='{self.actor_type}', category='{self.actor_category.value}', patterns={len(self.patterns)})"
