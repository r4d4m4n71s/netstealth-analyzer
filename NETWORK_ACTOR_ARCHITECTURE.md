# 🌐 Network Actor Architecture Guide

**Version**: 1.0.0  
**Author**: NetStealth Analyzer Team  
**Date**: September 19, 2025  

---

## 📋 Overview

The Network Actor Architecture provides a hierarchical, extensible system for identifying and analyzing network entities in the request path. This architecture moves beyond simple proxy detection to comprehensive network actor identification and behavioral analysis.

## 🎯 Goals

1. **Hierarchical Classification**: Organize network entities in a clear hierarchy
2. **Pattern-Based Detection**: Use configurable patterns for actor identification
3. **Behavioral Analysis**: Analyze actor behavior patterns and risks
4. **Extensibility**: Easy addition of new actor types and detection patterns
5. **Protocol Awareness**: Support multiple protocols (HTTP, WebSocket, gRPC, TCP)

---

## 🏗️ Architecture Overview

### Core Concepts

```
NetworkActor (Base)
├── ProxyActor
│   ├── HTTPProxy
│   ├── SOCKS4Proxy
│   ├── SOCKS5Proxy
│   └── TransparentProxy
├── VPNActor
│   ├── OpenVPN
│   ├── WireGuard
│   └── IPSec
├── CDNActor
│   ├── CloudFlare
│   ├── Akamai
│   └── Fastly
├── LoadBalancerActor
│   ├── HAProxy
│   ├── NGINX
│   └── AWS_ALB
└── SecurityServiceActor
    ├── WAF (Web Application Firewall)
    ├── DDoSProtection
    └── BotDetection
```

### Key Components

1. **NetworkActor**: Base class defining common interface
2. **ActorPattern**: Pattern matching for actor identification
3. **ActorRegistry**: Dynamic loading and management of actors
4. **BehaviorAnalyzer**: Analysis of actor behavior and risks
5. **DetectionContext**: Context for actor detection and analysis

---

## 🔍 Actor Detection Process

### 1. Pattern Matching Phase

Each actor defines patterns for identification:

```python
class ProxyActor(NetworkActor):
    patterns = [
        HeaderPattern("X-Forwarded-For", required=True),
        HeaderPattern("Via", confidence=0.8),
        IPRangePattern(datacenter_ranges, confidence=0.6),
        ResponsePattern("proxy.*detected", confidence=0.9)
    ]
```

### 2. Behavioral Analysis Phase

Once identified, actors are analyzed for:
- **Risk Assessment**: Security implications
- **Performance Impact**: Latency, reliability
- **Detection Likelihood**: Probability of being detected
- **Anonymity Level**: Transparency vs. anonymity

### 3. Cross-Actor Analysis

Multiple actors in the same trace are analyzed for:
- **Chain Consistency**: Logical actor sequences
- **Geographic Consistency**: Location alignment
- **Protocol Compatibility**: Protocol support across chain
- **Risk Aggregation**: Combined risk assessment

---

## 📁 Module Structure

```
src/netstealth_analyzer/actors/
├── __init__.py              # Module exports
├── base.py                  # NetworkActor base class
├── patterns.py              # Pattern matching classes
├── registry.py              # Actor registry
├── analyzer.py              # Behavioral analysis
├── proxy.py                 # ProxyActor implementation
├── vpn.py                   # VPNActor (future)
├── cdn.py                   # CDNActor (future)
├── loadbalancer.py          # LoadBalancerActor (future)
└── security.py              # SecurityServiceActor (future)
```

---

## 🔧 Implementation Guide

### Creating a New Actor

1. **Inherit from NetworkActor**:
```python
class MyActor(NetworkActor):
    actor_type = "my_actor"
    actor_category = "intermediary"
```

2. **Define Detection Patterns**:
```python
patterns = [
    HeaderPattern("X-My-Header"),
    IPRangePattern(my_ip_ranges),
    ResponsePattern("my.*signature")
]
```

3. **Implement Identification Logic**:
```python
def identify(self, hop: NetworkHop) -> ActorIdentification:
    # Custom identification logic
    pass
```

4. **Implement Behavioral Analysis**:
```python
def analyze_behavior(self, trace: NetworkTrace) -> BehaviorAnalysis:
    # Custom behavior analysis
    pass
```

5. **Register the Actor**:
```python
# In registry.py
register_actor("my_actor", MyActor)
```

### Pattern Types

#### HeaderPattern
Matches HTTP headers:
```python
HeaderPattern(
    name="X-Forwarded-For",
    required=True,
    confidence=0.9,
    value_pattern=r"\d+\.\d+\.\d+\.\d+"
)
```

#### IPRangePattern
Matches IP address ranges:
```python
IPRangePattern(
    ranges=["198.51.100.0/24", "203.0.113.0/24"],
    confidence=0.7,
    description="Datacenter IP ranges"
)
```

#### ResponsePattern
Matches response content:
```python
ResponsePattern(
    pattern=r"proxy.*detected",
    confidence=0.8,
    case_sensitive=False
)
```

#### PortPattern
Matches specific ports:
```python
PortPattern(
    ports=[8080, 3128, 1080],
    confidence=0.6,
    description="Common proxy ports"
)
```

---

## 🎯 Actor Types

### 1. ProxyActor (Implemented)

**Purpose**: Detect and analyze proxy servers in the request path.

**Detection Patterns**:
- HTTP headers: `X-Forwarded-For`, `Via`, `X-Real-IP`
- Datacenter IP ranges
- Proxy service domains
- Response content patterns

**Behavioral Analysis**:
- Anonymity level (transparent, anonymous, elite)
- Detection likelihood
- Geographic consistency
- Performance impact

**Subtypes**:
- `HTTPProxy`: HTTP/HTTPS proxies
- `SOCKS4Proxy`: SOCKS4 proxies
- `SOCKS5Proxy`: SOCKS5 proxies
- `TransparentProxy`: Transparent proxies

### 2. VPNActor (Future Implementation)

**Purpose**: Detect VPN services and analyze their characteristics.

**Detection Patterns**:
- VPN provider IP ranges
- OpenVPN signatures
- WireGuard patterns
- IPSec indicators

**Behavioral Analysis**:
- VPN provider identification
- Jurisdiction analysis
- Logging policies
- Performance characteristics

### 3. CDNActor (Future Implementation)

**Purpose**: Identify Content Delivery Network services.

**Detection Patterns**:
- CDN-specific headers
- Edge server identification
- Caching behavior
- Geographic distribution

**Behavioral Analysis**:
- CDN provider identification
- Edge location mapping
- Performance optimization
- Security features

### 4. LoadBalancerActor (Future Implementation)

**Purpose**: Detect load balancers and traffic distribution systems.

**Detection Patterns**:
- Load balancer headers
- Session affinity cookies
- Health check patterns
- Distribution algorithms

**Behavioral Analysis**:
- Load balancing strategy
- Backend server identification
- Failover behavior
- Performance characteristics

### 5. SecurityServiceActor (Future Implementation)

**Purpose**: Identify security services (WAF, DDoS protection, bot detection).

**Detection Patterns**:
- Security service headers
- Challenge-response patterns
- Rate limiting indicators
- Bot detection signatures

**Behavioral Analysis**:
- Security service type
- Protection mechanisms
- Bypass techniques
- Risk assessment

---

## 🔄 Integration with Existing System

### Detector Integration

Existing detectors (ProxyDetector, BrowserDetector, etc.) will use the actor system:

```python
class ProxyDetector(BaseDetector):
    def __init__(self):
        self.actor_registry = ActorRegistry()
        self.proxy_actor = self.actor_registry.get_actor("proxy")
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        # Use actor system for detection
        actors = await self.proxy_actor.identify_in_traces(context.network_traces)
        issues = await self.proxy_actor.analyze_behaviors(actors)
        return DetectionResult(issues_found=issues)
```

### Backward Compatibility

The new system maintains backward compatibility:
- Existing detectors continue to work
- Gradual migration to actor-based detection
- Legacy pattern support during transition

---

## 📊 Performance Considerations

### Pattern Matching Optimization

1. **Pattern Caching**: Cache compiled regex patterns
2. **Early Termination**: Stop matching on high-confidence identification
3. **Parallel Processing**: Process multiple traces concurrently
4. **Selective Analysis**: Skip detailed analysis for low-risk actors

### Memory Management

1. **Lazy Loading**: Load actors only when needed
2. **Pattern Sharing**: Share common patterns between actors
3. **Result Caching**: Cache identification results for similar traces
4. **Cleanup**: Proper cleanup of analysis results

---

## 🧪 Testing Strategy

### Unit Tests

1. **Pattern Matching Tests**: Verify pattern accuracy
2. **Actor Identification Tests**: Test identification logic
3. **Behavioral Analysis Tests**: Validate behavior analysis
4. **Registry Tests**: Test actor registration and loading

### Integration Tests

1. **End-to-End Detection**: Full detection pipeline tests
2. **Cross-Actor Analysis**: Multi-actor scenario tests
3. **Performance Tests**: Latency and throughput tests
4. **Compatibility Tests**: Backward compatibility verification

### Test Data

1. **Synthetic Traces**: Generated test traces for each actor type
2. **Real-World Samples**: Anonymized production traces
3. **Edge Cases**: Unusual configurations and error conditions
4. **Performance Benchmarks**: Large-scale test datasets

---

## 🚀 Future Enhancements

### Phase 1: Core Implementation ✅ COMPLETED
- [x] NetworkActor base class
- [x] Pattern matching system
- [x] ProxyActor implementation
- [x] Actor registry
- [x] Integration with existing detectors

### Phase 2: Extended Actor Types (Desired Future Implementation)
- [ ] VPNActor implementation
- [ ] CDNActor implementation
- [ ] LoadBalancerActor implementation
- [ ] SecurityServiceActor implementation

### Phase 3: Advanced Features (Desired Future Implementation)
- [ ] Machine learning-based actor identification
- [ ] Dynamic pattern learning
- [ ] Actor behavior prediction
- [ ] Real-time actor monitoring

### Phase 4: Enterprise Features (Desired Future Implementation)
- [ ] Custom actor definitions
- [ ] Actor behavior policies
- [ ] Compliance reporting
- [ ] Integration APIs

---

## 📚 References

### Standards and Protocols
- RFC 7230: HTTP/1.1 Message Syntax and Routing
- RFC 7231: HTTP/1.1 Semantics and Content
- RFC 1928: SOCKS Protocol Version 5
- RFC 2616: HTTP/1.1 (obsoleted by RFC 7230-7235)

### Security Resources
- OWASP Proxy Detection Guide
- NIST Cybersecurity Framework
- Common Vulnerability Scoring System (CVSS)

### Implementation References
- Python Type Hints (PEP 484, 526, 544)
- Pydantic Data Validation
- AsyncIO Best Practices
- Design Patterns in Python

---

**Document Status**: Draft v1.0  
**Last Updated**: September 19, 2025  
**Next Review**: October 19, 2025
