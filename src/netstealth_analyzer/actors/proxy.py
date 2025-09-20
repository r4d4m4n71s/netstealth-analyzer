"""
Proxy Actor implementation for the Network Actor Detection System.

This module implements comprehensive proxy detection and behavioral analysis
using the hierarchical network actor architecture.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .base import (
    NetworkActor, ActorCategory, ActorIdentification, BehaviorAnalysis,
    AnonymityLevel, HeaderPattern, IPRangePattern, ResponsePattern, PortPattern
)
from ..models.enums import RiskLevel
from ..models.network import NetworkTrace, NetworkHop
from ..compatibility import override


class ProxyActor(NetworkActor):
    """
    Network actor for detecting and analyzing proxy servers.
    
    This actor identifies various types of proxy servers including HTTP proxies,
    SOCKS proxies, and transparent proxies using multiple detection patterns.
    """
    
    def __init__(self):
        """Initialize ProxyActor with detection patterns."""
        super().__init__()
        
        # Datacenter IP ranges (common proxy hosting providers)
        self._datacenter_ranges = [
            # AWS
            "3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8",
            "35.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8",
            # Google Cloud
            "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/11",
            # Azure
            "13.64.0.0/11", "20.0.0.0/8", "40.0.0.0/8",
            # DigitalOcean
            "104.131.0.0/16", "138.197.0.0/16", "159.203.0.0/16",
            # Linode
            "45.33.0.0/16", "45.56.0.0/16", "50.116.0.0/16",
            # Vultr
            "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16",
            # OVH
            "51.254.0.0/16", "54.36.0.0/16", "91.121.0.0/16",
            # Hetzner
            "5.9.0.0/16", "78.46.0.0/15", "88.99.0.0/16",
            # Common proxy service ranges
            "198.51.100.0/24", "203.0.113.0/24"
        ]
        
        # Residential proxy service domains and indicators
        self._residential_proxy_domains = [
            'brightdata.com', 'luminati.io', 'oxylabs.io', 'smartproxy.com',
            'soax.com', 'netnut.io', 'geosurf.com', 'rayobyte.com',
            'storm-proxies.com', 'proxy-seller.com', 'proxyrack.com',
            'shifter.io', 'microleaves.com', 'blazingseollc.com'
        ]
        
        # ISP ranges that are commonly used for residential proxies
        # These are major ISPs whose IP ranges might indicate residential usage
        self._major_isp_indicators = [
            'comcast', 'verizon', 'att', 'charter', 'cox', 'centurylink',
            'frontier', 'windstream', 'mediacom', 'suddenlink',
            'bt', 'virgin', 'sky', 'talktalk', 'plusnet',  # UK ISPs
            'deutsche telekom', 'vodafone', 'o2', 'telefonica',  # EU ISPs
            'ntt', 'softbank', 'kddi',  # Japan ISPs
            'china telecom', 'china unicom', 'china mobile'  # China ISPs
        ]
        
        # Common proxy service domains
        self._proxy_service_domains = [
            'proxy-seller.com', 'smartproxy.com', 'oxylabs.io',
            'bright-data.com', 'storm-proxies.com', 'proxy-cheap.com',
            'myprivateproxy.net', 'blazingseollc.com', 'proxyrack.com',
            'rayobyte.com', 'soax.com', 'netnut.io'
        ]
        
        # Common proxy ports
        self._proxy_ports = [
            3128, 8080, 8888, 1080, 1081, 9050, 9051,  # Standard proxy ports
            8000, 8001, 8008, 8118, 8123, 8888, 9000,  # Alternative HTTP proxy ports
            1085, 1086, 1087, 1088, 1089, 1090,        # SOCKS proxy ports
        ]
    
    @property
    @override
    def actor_type(self) -> str:
        """Get the actor type identifier."""
        return "proxy"
    
    @property
    @override
    def actor_category(self) -> ActorCategory:
        """Get the actor category."""
        return ActorCategory.PROXY
    
    @property
    @override
    def patterns(self) -> List:
        """Get detection patterns for proxy identification."""
        return [
            # HTTP proxy headers (high confidence indicators)
            HeaderPattern(
                "x-forwarded-for",
                confidence=0.9,
                description="X-Forwarded-For header indicates proxy usage"
            ),
            HeaderPattern(
                "via",
                confidence=0.85,
                description="Via header indicates proxy in request path"
            ),
            HeaderPattern(
                "x-real-ip",
                confidence=0.8,
                description="X-Real-IP header indicates reverse proxy"
            ),
            HeaderPattern(
                "x-forwarded-proto",
                confidence=0.7,
                description="X-Forwarded-Proto header indicates proxy"
            ),
            HeaderPattern(
                "x-forwarded-host",
                confidence=0.7,
                description="X-Forwarded-Host header indicates proxy"
            ),
            HeaderPattern(
                "proxy-authorization",
                confidence=0.95,
                description="Proxy-Authorization header indicates authenticated proxy"
            ),
            HeaderPattern(
                "x-proxy-authorization",
                confidence=0.9,
                description="X-Proxy-Authorization header indicates proxy authentication"
            ),
            
            # Datacenter IP ranges (medium confidence for datacenter proxies)
            IPRangePattern(
                self._datacenter_ranges,
                confidence=0.6,
                description="IP address from known datacenter/hosting provider"
            ),
            
            # Common proxy ports (low-medium confidence)
            PortPattern(
                self._proxy_ports,
                confidence=0.5,
                description="Connection to common proxy port"
            ),
            
            # Response content patterns indicating proxy detection
            ResponsePattern(
                r"proxy.*detected|using.*proxy|proxy.*blocked|proxy.*not.*allowed",
                confidence=0.9,
                description="Response content indicates proxy detection"
            ),
            ResponsePattern(
                r"datacenter.*ip|hosting.*provider|commercial.*proxy|vps.*detected",
                confidence=0.7,
                description="Response indicates datacenter IP detection"
            ),
            ResponsePattern(
                r"residential.*proxy.*detected|home.*ip.*detected|isp.*proxy.*detected",
                confidence=0.8,
                description="Response indicates residential proxy detection"
            ),
            ResponsePattern(
                r"vpn.*detected|tunnel.*detected|anonymizer.*detected",
                confidence=0.8,
                description="Response indicates VPN/anonymizer detection"
            ),
            
            # WebRTC leak indicators
            ResponsePattern(
                r"webrtc.*leak|stun.*server|ice.*candidate",
                confidence=0.85,
                description="WebRTC leak detection in response"
            ),
            
            # IP leak patterns
            ResponsePattern(
                r"real.*ip.*detected|original.*ip.*found|ip.*leak.*detected|dns.*leak",
                confidence=0.9,
                description="IP leak detection in response"
            )
        ]
    
    @override
    def analyze_behavior(self, trace: NetworkTrace, identification: ActorIdentification) -> BehaviorAnalysis:
        """
        Analyze proxy behavior and characteristics.
        
        Args:
            trace: Network trace containing the proxy
            identification: Proxy identification result
            
        Returns:
            BehaviorAnalysis with proxy-specific risk assessment
        """
        # Initialize analysis components
        risk_factors = []
        characteristics = {}
        recommendations = []
        
        # Analyze proxy detection indicators
        detection_likelihood = self._analyze_detection_likelihood(trace, identification)
        anonymity_level = self._analyze_anonymity_level(trace, identification)
        
        # Calculate risk score based on various factors
        risk_score = self._calculate_risk_score(trace, identification, detection_likelihood)
        
        # Determine overall risk level
        if risk_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.SAFE
        
        # Analyze proxy characteristics
        characteristics.update(self._analyze_proxy_characteristics(trace, identification))
        
        # Generate recommendations based on analysis
        recommendations.extend(self._generate_recommendations(
            risk_level, anonymity_level, detection_likelihood, characteristics
        ))
        
        # Assess performance impact
        performance_impact = self._assess_performance_impact(trace, characteristics)
        
        return BehaviorAnalysis(
            risk_level=risk_level,
            risk_score=risk_score,
            anonymity_level=anonymity_level,
            detection_likelihood=detection_likelihood,
            performance_impact=performance_impact,
            characteristics=characteristics,
            recommendations=recommendations
        )
    
    def _analyze_detection_likelihood(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification
    ) -> float:
        """Analyze likelihood of proxy detection by target service."""
        detection_score = 0.0
        
        # Check for explicit proxy detection messages in patterns
        patterns_str = str(identification.patterns_matched).lower()
        if "proxy" in patterns_str and ("detected" in patterns_str or "blocked" in patterns_str):
            detection_score += 0.4
        
        # Check for datacenter IP detection
        if "datacenter" in patterns_str or "hosting" in patterns_str:
            detection_score += 0.3
        
        # Check for IP leak indicators
        if "leak" in patterns_str:
            detection_score += 0.3
        
        # Check for proxy headers (increases detection likelihood)
        if "x-forwarded-for" in patterns_str or "via" in patterns_str or "x-real-ip" in patterns_str:
            detection_score += 0.2
        
        # Check response body for proxy detection messages
        if trace.is_http() and trace.http_data and trace.http_data.response and trace.http_data.response.body:
            response_body = str(trace.http_data.response.body).lower()
            if "proxy" in response_body and ("detected" in response_body or "blocked" in response_body):
                detection_score += 0.3
        
        # Check response status codes that might indicate blocking
        if (trace.is_http() and trace.http_data and trace.http_data.response and
            trace.http_data.response.status_code in [403, 429, 503]):
            detection_score += 0.2
        
        return min(1.0, detection_score)
    
    def _analyze_anonymity_level(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification
    ) -> AnonymityLevel:
        """Analyze the anonymity level provided by the proxy."""
        
        # Check for transparent proxy indicators
        transparent_indicators = [
            "x-forwarded-for", "x-real-ip", "x-forwarded-proto"
        ]
        
        if trace.is_http() and trace.http_data and trace.http_data.request:
            headers_present = [
                header.get('name', '').lower() 
                for header in trace.http_data.request.headers
            ]
            
            # If forwarding headers are present, it's likely transparent
            if any(indicator in headers_present for indicator in transparent_indicators):
                return AnonymityLevel.TRANSPARENT
        
        # Check for elite proxy indicators (no revealing headers)
        if not any("header" in pattern.lower() for pattern in identification.patterns_matched):
            # If detected only by IP range or response patterns, might be elite
            if any("ip" in pattern.lower() or "response" in pattern.lower() 
                   for pattern in identification.patterns_matched):
                return AnonymityLevel.ELITE
        
        # Default to anonymous if some headers but not all transparent indicators
        return AnonymityLevel.ANONYMOUS
    
    def _calculate_risk_score(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification,
        detection_likelihood: float
    ) -> float:
        """Calculate overall risk score for proxy usage."""
        risk_score = 0.0
        
        # Base risk from detection likelihood
        risk_score += detection_likelihood * 0.4
        
        # Risk from confidence level
        risk_score += identification.confidence * 0.2
        
        # Risk from number of patterns matched
        pattern_risk = min(0.3, len(identification.patterns_matched) * 0.05)
        risk_score += pattern_risk
        
        # Additional risk factors
        if trace.is_http() and trace.http_data:
            # Risk from response status codes
            if (trace.http_data.response and 
                trace.http_data.response.status_code in [403, 429, 503]):
                risk_score += 0.2
            
            # Risk from proxy service domains
            if trace.http_data.request:
                domain = self._extract_domain(trace.http_data.request.url)
                if any(service in domain for service in self._proxy_service_domains):
                    risk_score += 0.3
        
        return min(1.0, risk_score)
    
    def _analyze_proxy_characteristics(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification
    ) -> Dict[str, Any]:
        """Analyze specific characteristics of the proxy."""
        characteristics = {
            'proxy_type': 'unknown',
            'proxy_subtype': 'unknown',  # datacenter, residential, mobile
            'headers_detected': [],
            'ports_detected': [],
            'ip_ranges_matched': [],
            'response_patterns': [],
            'geographic_info': None,
            'residential_indicators': [],
            'datacenter_indicators': []
        }
        
        # Analyze detected headers
        if trace.is_http() and trace.http_data and trace.http_data.request:
            proxy_headers = []
            for header in trace.http_data.request.headers:
                header_name = header.get('name', '').lower()
                if header_name in ['x-forwarded-for', 'via', 'x-real-ip', 
                                  'x-forwarded-proto', 'x-forwarded-host',
                                  'proxy-authorization', 'x-proxy-authorization']:
                    proxy_headers.append({
                        'name': header_name,
                        'value': header.get('value', '')
                    })
            characteristics['headers_detected'] = proxy_headers
        
        # Determine proxy type and subtype based on patterns
        if any('socks' in pattern.lower() for pattern in identification.patterns_matched):
            characteristics['proxy_type'] = 'socks'
        elif any('http' in pattern.lower() for pattern in identification.patterns_matched):
            characteristics['proxy_type'] = 'http'
        elif any('transparent' in pattern.lower() for pattern in identification.patterns_matched):
            characteristics['proxy_type'] = 'transparent'
        
        # Determine proxy subtype (residential vs datacenter)
        characteristics['proxy_subtype'] = self._determine_proxy_subtype(trace, identification)
        
        # Analyze residential vs datacenter indicators
        characteristics['residential_indicators'] = self._get_residential_indicators(trace)
        characteristics['datacenter_indicators'] = self._get_datacenter_indicators(trace)
        
        # Analyze geographic information from hops
        if trace.hops:
            geographic_info = []
            for hop in trace.hops:
                if hop.geographic_info:
                    geographic_info.append({
                        'country': hop.geographic_info.country_code,
                        'city': hop.geographic_info.city,
                        'isp': hop.geographic_info.isp
                    })
            characteristics['geographic_info'] = geographic_info
        
        # Analyze response patterns
        response_patterns = []
        for pattern in identification.patterns_matched:
            if 'response' in pattern.lower():
                response_patterns.append(pattern)
        characteristics['response_patterns'] = response_patterns
        
        return characteristics
    
    def _generate_recommendations(
        self,
        risk_level: RiskLevel,
        anonymity_level: AnonymityLevel,
        detection_likelihood: float,
        characteristics: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on proxy analysis."""
        recommendations = []
        
        # Always provide basic recommendations for any proxy usage
        recommendations.extend([
            "Monitor proxy performance and reliability",
            "Regularly test proxy anonymity levels",
            "Keep proxy configurations updated"
        ])
        
        # High-risk recommendations
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.extend([
                "Switch to residential proxy IPs immediately",
                "Change proxy provider to avoid detection",
                "Implement advanced proxy rotation strategy",
                "Consider using mobile proxy networks"
            ])
        
        # Medium-risk recommendations
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Consider upgrading to residential proxies",
                "Implement proxy rotation to reduce detection",
                "Monitor for detection patterns"
            ])
        
        # Low-risk recommendations
        elif risk_level == RiskLevel.LOW:
            recommendations.extend([
                "Continue monitoring proxy performance",
                "Consider periodic proxy rotation",
                "Verify proxy anonymity periodically"
            ])
        
        # Anonymity-based recommendations
        if anonymity_level == AnonymityLevel.TRANSPARENT:
            recommendations.extend([
                "Configure proxy to strip forwarding headers",
                "Use header manipulation tools",
                "Switch to anonymous or elite proxy configuration"
            ])
        elif anonymity_level == AnonymityLevel.ANONYMOUS:
            recommendations.extend([
                "Upgrade to elite proxy configuration",
                "Verify no client information is leaked"
            ])
        
        # Detection likelihood recommendations
        if detection_likelihood > 0.7:
            recommendations.extend([
                "Implement request randomization",
                "Add realistic browser fingerprinting",
                "Use different user agents and headers",
                "Implement session management"
            ])
        elif detection_likelihood > 0.3:
            recommendations.extend([
                "Monitor for detection patterns",
                "Consider request pattern randomization"
            ])
        
        # Header-specific recommendations
        if characteristics.get('headers_detected'):
            recommendations.extend([
                "Remove or modify proxy-revealing headers",
                "Implement header filtering at proxy level",
                "Use middleware to clean request headers"
            ])
        
        # Geographic recommendations
        if characteristics.get('geographic_info'):
            recommendations.extend([
                "Verify geographic consistency of proxy chain",
                "Use proxies from target service's region",
                "Avoid suspicious geographic patterns"
            ])
        
        # Datacenter proxy recommendations
        if characteristics.get('proxy_subtype') == 'datacenter':
            recommendations.extend([
                "Consider switching to residential proxies for better anonymity",
                "Use datacenter proxies for high-speed requirements only"
            ])
        
        # Residential proxy recommendations
        elif characteristics.get('proxy_subtype') == 'residential':
            recommendations.extend([
                "Maintain residential proxy quality",
                "Monitor for ISP blocking patterns"
            ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _assess_performance_impact(
        self, 
        trace: NetworkTrace, 
        characteristics: Dict[str, Any]
    ) -> str:
        """Assess performance impact of proxy usage."""
        
        # Analyze timing information if available
        if (trace.is_http() and trace.http_data and trace.http_data.timing and
            trace.http_data.timing.total_time > 0):
            
            total_time = trace.http_data.timing.total_time
            
            if total_time > 5000:  # > 5 seconds
                return "High latency impact - consider faster proxy provider"
            elif total_time > 2000:  # > 2 seconds
                return "Moderate latency impact - acceptable for most use cases"
            else:
                return "Low latency impact - good proxy performance"
        
        # Analyze hop count
        if len(trace.hops) > 3:
            return "Multiple hops detected - may impact performance"
        elif len(trace.hops) > 1:
            return "Moderate proxy chain - normal performance impact"
        else:
            return "Direct proxy connection - minimal performance impact"
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    def get_proxy_subtypes(self) -> List[str]:
        """Get list of proxy subtypes this actor can identify."""
        return [
            "http_proxy",
            "https_proxy", 
            "socks4_proxy",
            "socks5_proxy",
            "transparent_proxy",
            "reverse_proxy",
            "forward_proxy"
        ]
    
    def identify_proxy_subtype(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification
    ) -> Optional[str]:
        """
        Identify specific proxy subtype based on patterns.
        
        Args:
            trace: Network trace containing proxy
            identification: Proxy identification result
            
        Returns:
            Proxy subtype string or None if cannot determine
        """
        patterns_str = str(identification.patterns_matched).lower()
        
        # Check for HTTP proxy indicators first (most common)
        if trace.is_http():
            http_indicators = ["x-forwarded-for", "via", "x-forwarded-proto", "x-forwarded-host"]
            if any(header in patterns_str for header in http_indicators):
                return "http_proxy"
        
        # Check for transparent proxy indicators
        if "x-real-ip" in patterns_str:
            return "transparent_proxy"
        
        # Check for SOCKS proxy indicators (check ports in trace)
        if trace.hops:
            for hop in trace.hops:
                if hop.connection_info:
                    if (hop.connection_info.destination_port in [1080, 1081, 1085, 1086, 1087, 1088] or
                        hop.connection_info.source_port in [1080, 1081, 1085, 1086, 1087, 1088]):
                        return "socks_proxy"
        
        # Check for SOCKS patterns in matched patterns
        if "socks" in patterns_str:
            return "socks_proxy"
        
        return "http_proxy"  # Default to http_proxy for HTTP traces
    
    def _determine_proxy_subtype(
        self, 
        trace: NetworkTrace, 
        identification: ActorIdentification
    ) -> str:
        """
        Determine if proxy is residential, datacenter, or mobile.
        
        Args:
            trace: Network trace containing proxy
            identification: Proxy identification result
            
        Returns:
            Proxy subtype: 'residential', 'datacenter', 'mobile', or 'unknown'
        """
        residential_score = 0
        datacenter_score = 0
        mobile_score = 0
        
        # Check for datacenter IP ranges
        if any("datacenter" in pattern.lower() or "hosting" in pattern.lower() 
               for pattern in identification.patterns_matched):
            datacenter_score += 3
        
        # Check for residential proxy service domains
        if trace.is_http() and trace.http_data and trace.http_data.request:
            domain = self._extract_domain(trace.http_data.request.url)
            if any(service in domain for service in self._residential_proxy_domains):
                residential_score += 2
        
        # Analyze geographic information and ISP data
        if trace.hops:
            for hop in trace.hops:
                if hop.geographic_info and hop.geographic_info.isp:
                    isp_name = hop.geographic_info.isp.lower()
                    
                    # Check for major ISP indicators (suggests residential)
                    if any(isp in isp_name for isp in self._major_isp_indicators):
                        residential_score += 2
                    
                    # Check for hosting/datacenter indicators
                    datacenter_keywords = [
                        'hosting', 'datacenter', 'cloud', 'server', 'vps',
                        'dedicated', 'colocation', 'colo', 'aws', 'azure',
                        'google cloud', 'digital ocean', 'linode', 'vultr'
                    ]
                    if any(keyword in isp_name for keyword in datacenter_keywords):
                        datacenter_score += 2
                    
                    # Check for mobile indicators
                    mobile_keywords = [
                        'mobile', 'cellular', 'wireless', '4g', '5g', 'lte',
                        't-mobile', 'verizon wireless', 'att mobility'
                    ]
                    if any(keyword in isp_name for keyword in mobile_keywords):
                        mobile_score += 2
        
        # Check response patterns for specific detection messages
        for pattern in identification.patterns_matched:
            if 'residential' in pattern.lower():
                residential_score += 2
            elif 'datacenter' in pattern.lower() or 'hosting' in pattern.lower():
                datacenter_score += 2
            elif 'mobile' in pattern.lower() or 'cellular' in pattern.lower():
                mobile_score += 2
        
        # Determine subtype based on scores
        max_score = max(residential_score, datacenter_score, mobile_score)
        
        if max_score == 0:
            return 'unknown'
        elif residential_score == max_score:
            return 'residential'
        elif datacenter_score == max_score:
            return 'datacenter'
        elif mobile_score == max_score:
            return 'mobile'
        else:
            return 'unknown'
    
    def _get_residential_indicators(self, trace: NetworkTrace) -> List[str]:
        """Get indicators that suggest residential proxy usage."""
        indicators = []
        
        # Check for residential proxy service domains
        if trace.is_http() and trace.http_data and trace.http_data.request:
            domain = self._extract_domain(trace.http_data.request.url)
            for service in self._residential_proxy_domains:
                if service in domain:
                    indicators.append(f"Residential proxy service domain: {service}")
        
        # Check ISP information
        if trace.hops:
            for hop in trace.hops:
                if hop.geographic_info and hop.geographic_info.isp:
                    isp_name = hop.geographic_info.isp.lower()
                    for isp in self._major_isp_indicators:
                        if isp in isp_name:
                            indicators.append(f"Major ISP detected: {hop.geographic_info.isp}")
                            break
        
        # Check for residential-specific response patterns
        if trace.is_http() and trace.http_data and trace.http_data.response:
            response_body = str(trace.http_data.response.body).lower()
            residential_patterns = [
                'residential.*proxy', 'home.*ip', 'isp.*proxy', 'real.*user.*ip'
            ]
            for pattern in residential_patterns:
                if re.search(pattern, response_body):
                    indicators.append(f"Residential detection pattern: {pattern}")
        
        return indicators
    
    def _get_datacenter_indicators(self, trace: NetworkTrace) -> List[str]:
        """Get indicators that suggest datacenter proxy usage."""
        indicators = []
        
        # Check for datacenter IP ranges
        if trace.hops:
            for hop in trace.hops:
                for ip_str in [hop.incoming_ip, hop.outgoing_ip]:
                    try:
                        ip_addr = ipaddress.ip_address(ip_str)
                        for network in [ipaddress.ip_network(range_str, strict=False) 
                                      for range_str in self._datacenter_ranges]:
                            if ip_addr in network:
                                indicators.append(f"Datacenter IP range: {network}")
                                break
                    except ValueError:
                        continue
        
        # Check ISP information for hosting providers
        if trace.hops:
            for hop in trace.hops:
                if hop.geographic_info and hop.geographic_info.isp:
                    isp_name = hop.geographic_info.isp.lower()
                    datacenter_keywords = [
                        'hosting', 'datacenter', 'cloud', 'server', 'vps',
                        'dedicated', 'colocation', 'aws', 'azure', 'google cloud'
                    ]
                    for keyword in datacenter_keywords:
                        if keyword in isp_name:
                            indicators.append(f"Datacenter ISP: {hop.geographic_info.isp}")
                            break
        
        # Check for datacenter-specific response patterns
        if trace.is_http() and trace.http_data and trace.http_data.response:
            response_body = str(trace.http_data.response.body).lower()
            datacenter_patterns = [
                'datacenter.*ip', 'hosting.*provider', 'commercial.*proxy', 'vps.*detected'
            ]
            for pattern in datacenter_patterns:
                if re.search(pattern, response_body):
                    indicators.append(f"Datacenter detection pattern: {pattern}")
        
        return indicators
