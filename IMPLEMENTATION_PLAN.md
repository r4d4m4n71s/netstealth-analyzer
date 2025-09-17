# 🚀 NetStealth Analyzer v2.0 - Unified Implementation Plan

**Project Status**: 80% Complete  
**Python Version**: 3.13.7  
**Architecture**: Async-first, Event-driven, Plugin-based  
**Test Coverage**: 48% overall, 99% core components  
**Test Status**: 713/714 tests passing (99.86%)  

---

## 🏗️ System Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           NetStealth Analyzer v2.0                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐          │
│  │   Input Layer   │     │  Analysis Core  │     │  Output Layer   │          │
│  ├─────────────────┤     ├─────────────────┤     ├─────────────────┤          │
│  │ • HAR Files     │────▶│ • Pipeline Eng. │────▶│ • JSON Reports  │          │
│  │ • Mitmproxy     │     │ • Event Bus     │     │ • HTML Reports  │          │
│  │ • Browser Logs  │     │ • Detectors     │     │ • Markdown      │          │
│  │ • POC Results   │     │ • Analyzers     │     │ • YAML Reports  │          │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘          │
│           │                       │                        │                    │
│           ▼                       ▼                        ▼                    │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐          │
│  │    Parsers      │     │     Models      │     │   Reporters     │          │
│  ├─────────────────┤     ├─────────────────┤     ├─────────────────┤          │
│  │ • HAR Parser    │     │ • NetworkTrace  │     │ • Incremental   │          │
│  │ • Mitmproxy     │     │ • NetworkHop    │     │ • Streaming     │          │
│  │ • Browser       │     │ • ConnectionInfo│     │ • Formatters    │          │
│  │ • POC Parser    │     │ • Issue Models  │     │ • Templates     │          │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘          │
│                                     │                                           │
│                          ┌──────────┴──────────┐                               │
│                          │   Plugin System     │                               │
│                          ├────────────────────┤                               │
│                          │ • Dynamic Loading  │                               │
│                          │ • Sandboxing       │                               │
│                          │ • Registry         │                               │
│                          └────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Component Architecture

```
1. Fluent API Layer
   NetStealthAnalyzer.create()
       .with_logs("session.har")
       .for_service("example.com")
       .track_progress(callback)
       .build()

2. Core Processing Pipeline
   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
   │  Parse   │───▶│  Detect  │───▶│ Analyze  │───▶│  Report  │
   └──────────┘    └──────────┘    └──────────┘    └──────────┘
        │               │               │               │
        ▼               ▼               ▼               ▼
   [EventBus] ←─── Progress Events ───────────────────────┘

3. Model Relationships
   NetworkTrace
       └── NetworkHop[]
           ├── ConnectionInfo
           ├── TLSInfo
           ├── ProxyInfo
           └── GeographicInfo

   HttpRequest/HttpResponse (separate for HAR parsing)
       └── TimingInfo
```

### Event-Driven Architecture

```python
# Event Flow
EventBus
    ├── ANALYSIS_STARTED
    ├── PARSER_STARTED/COMPLETED
    ├── DETECTOR_STARTED/COMPLETED
    ├── ISSUE_FOUND
    ├── PROGRESS_UPDATE
    └── ANALYSIS_COMPLETED/FAILED
```

---

## ✅ Complete Implementation Checklist

### 🟢 COMPLETED (80%)

#### Phase 1: Project Setup & Core Infrastructure ✅
- [x] Create new project structure with Poetry
- [x] Set up pyproject.toml with Python 3.13+ requirements
- [x] Initialize git repository
- [x] Create compatibility layer (`src/netstealth_analyzer/compatibility.py`)
- [x] Configure all project dependencies
- [x] Set up pre-commit hooks structure

#### Phase 2: Core Components ✅
- [x] **EventBus System** (`core/events.py`)
  - Async event handling
  - Progress tracking
  - Real-time notifications
- [x] **Error Handling Architecture** (`core/errors.py`)
  - Structured error hierarchy
  - Recovery strategies
  - Context preservation
- [x] **Abstract Interfaces** (`core/interfaces.py`)
  - IComponent base class
  - ILogParser interface
  - IDetector interface
  - IReporter interface
- [x] **Pipeline Engine** (`core/pipeline.py`)
  - Async processing pipeline
  - Stage management
  - Error propagation
- [x] **Configuration Models** (`config.py`)
  - Pydantic v2 models
  - Validation logic
  - Default values

#### Phase 3: Models & Data Structures ✅
- [x] **Issue Models** (`models/issues.py`)
  - Issue class with severity/category
  - IssueEvidence for proof
  - DetectionRule for patterns
- [x] **Network Models** (`models/network.py`)
  - NetworkTrace (routing information)
  - NetworkHop (individual hops)
  - ConnectionInfo (connection details)
  - TLSInfo (encryption details)
  - ProxyInfo (proxy detection)
  - GeographicInfo (location data)
- [x] **Result Models** (`models/results.py`)
  - AnalysisResult
  - ExecutionContext
  - PerformanceMetrics
  - ProcessingStats
- [x] **Enumerations** (`models/enums.py`)
  - All enum types implemented
- [x] **HTTP Models** (added to `models/network.py`)
  - HttpRequest
  - HttpResponse
  - TimingInfo

#### Phase 4: Fluent API & Builder ✅
- [x] **AnalyzerBuilder** (`builder.py`)
  - Method chaining implementation
  - Comprehensive validation
  - Configuration options
- [x] **Main Analyzer** (`analyzer.py`)
  - Async analysis methods
  - Stream processing support
  - Context management

#### Phase 5: Parsers ✅
- [x] **ILogParser Interface** (`parsers/base.py`)
- [x] **HAR Parser** (`parsers/har.py`) - ⚠️ 10% test coverage
- [x] **Mitmproxy Parser** (`parsers/mitmproxy.py`) - ⚠️ 11% test coverage
- [x] **Browser Parser** (`parsers/browser.py`)
- [x] **POC Parser** (`parsers/poc.py`)
- [x] All parsers support async operations

#### Phase 6: Detectors ✅
- [x] **IDetector Interface** (`detectors/base.py`)
- [x] **TLS Detector** (`detectors/tls.py`)
- [x] **Proxy Detector** (`detectors/proxy.py`)
- [x] **Browser Detector** (`detectors/browser.py`) - ⚠️ 0% test coverage
- [x] **Network Detector** (`detectors/network.py`) - ⚠️ 0% test coverage
- [x] **Detector Registry** (`detectors/registry.py`)

#### Phase 7: Reporting System ✅
- [x] **IncrementalReporter** (`reporting/reporter.py`)
- [x] **Format Support** (`reporting/formats.py`)
  - JSON formatter
  - Markdown formatter
  - HTML formatter
  - YAML formatter
- [x] **Streaming Support**
- [x] **Report Templates**

#### Phase 8: Plugin System ✅
- [x] **Plugin Interfaces** (`plugins/base.py`)
- [x] **Plugin Registry** (`plugins/registry.py`)
- [x] **Plugin Loader** (`plugins/loader.py`)
- [x] **Plugin Sandboxing** (`plugins/sandbox.py`)
- [x] Windows compatibility for resource limits

#### Testing Phases 1-4a ✅
- [x] **Unit Tests**: 668 tests implemented
- [x] **Integration Tests**: 45 tests implemented
- [x] **Test Results**: 713 passing, 1 skipped (99.86%)
- [x] **Critical Fixes**:
  - NetworkHop field corrections
  - Integration test model fixes
  - Event system validation
- [x] **ConnectionInfo Integration Tests**:
  - Parser integration
  - Security integration
  - Performance integration
  - Quality assessment
  - Event-driven workflows

#### Python 3.13 Compatibility ✅
- [x] Pydantic v2 migration completed
- [x] All validators updated to v2 syntax
- [x] Compatibility test suite passing
- [x] Python 3.13 features enabled

---

### 🔴 PENDING (20%)

#### Issue 1: Browser Detector Test Failures (CRITICAL) 🚨
**Problem**: Tests expect NetworkTrace to have `request`/`response` attributes that don't exist

**Current Code (WRONG)**:
```python
# In test_detectors_browser.py
trace = NetworkTrace(
    id='selenium_trace',
    request=request,      # ❌ NetworkTrace doesn't have this
    response=response     # ❌ NetworkTrace doesn't have this
)
```

**Fix Required**:
```python
# Option 1: Store HTTP data in metadata
trace = NetworkTrace(
    trace_id='selenium_trace',
    metadata={
        'http_request': request.model_dump(),
        'http_response': response.model_dump()
    }
)

# Option 2: Update detector to work with NetworkHop model
hop = NetworkHop(
    hop_number=1,
    actor="browser",
    actor_name="Chrome/Selenium",
    incoming_ip="127.0.0.1",
    outgoing_ip="93.184.216.34",
    metadata={
        'user_agent': 'Mozilla/5.0...',
        'automation_detected': True
    }
)
```

**Tasks**:
- [ ] Analyze browser detector's actual needs
- [ ] Redesign test data structure
- [ ] Update all 16 failing tests
- [ ] Ensure detector works with NetworkTrace/NetworkHop model

#### Issue 2: Network Detector Tests (0% Coverage)
**File**: `tests/unit/test_detectors_network.py` (CREATE NEW)

**Implementation Needed**:
```python
import pytest
from src.netstealth_analyzer.detectors.network import NetworkDetector
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop
from src.netstealth_analyzer.models.enums import RiskLevel

class TestNetworkDetector:
    @pytest.fixture
    def network_detector(self):
        return NetworkDetector()
    
    async def test_detect_unusual_routing(self, network_detector):
        """Test detection of unusual network routing patterns."""
        # Create trace with suspicious routing
        hops = [
            NetworkHop(
                hop_number=1,
                actor="client",
                actor_name="User PC",
                incoming_ip="192.168.1.100",
                outgoing_ip="192.168.1.1"
            ),
            NetworkHop(
                hop_number=2,
                actor="proxy",
                actor_name="Unknown Proxy",
                incoming_ip="192.168.1.1",
                outgoing_ip="185.220.101.45",  # Tor exit node
                anomalies=["tor_exit_node"],
                risk_level=RiskLevel.HIGH
            )
        ]
        
        trace = NetworkTrace(hops=hops)
        context = DetectionContext(
            network_traces=[trace],
            service_domains=['example.com']
        )
        
        result = await network_detector.detect(context)
        assert len(result.issues_found) > 0
        assert any(issue.title == "Tor Exit Node Detected" 
                  for issue in result.issues_found)
```

**Tasks**:
- [ ] Create test file structure
- [ ] Test routing anomaly detection
- [ ] Test geographic inconsistencies
- [ ] Test latency pattern analysis
- [ ] Test proxy chain detection
- [ ] Achieve 80% coverage

#### Issue 3: HAR Parser Tests (10% → 80% Coverage)
**File**: `tests/unit/test_parsers_har.py` (EXPAND)

**Additional Tests Needed**:
```python
async def test_parse_large_har_file():
    """Test efficient parsing of large HAR files."""
    large_har = {
        "log": {
            "version": "1.2",
            "entries": [create_har_entry(i) for i in range(1000)]
        }
    }
    
    parser = HarParser()
    result = await parser.parse(large_har)
    assert len(result.network_traces) == 1000

async def test_extract_tls_info_from_har():
    """Test TLS information extraction."""
    har_with_tls = {
        "log": {
            "entries": [{
                "_securityState": "secure",
                "_tls": {
                    "version": "TLS 1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384"
                }
            }]
        }
    }
    
    parser = HarParser()
    result = await parser.parse(har_with_tls)
    # Verify TLS info extracted correctly
```

**Tasks**:
- [ ] Add large file handling tests
- [ ] Add malformed data tests
- [ ] Add TLS extraction tests
- [ ] Add streaming parse tests
- [ ] Add edge case tests
- [ ] Achieve 80% coverage

#### Issue 4: Mitmproxy Parser Tests (11% → 80% Coverage)
**File**: `tests/unit/test_parsers_mitmproxy.py` (EXPAND)

**Tasks**:
- [ ] Add WebSocket flow tests
- [ ] Add HTTP/2 flow tests
- [ ] Add certificate extraction tests
- [ ] Add error handling tests
- [ ] Add performance tests
- [ ] Achieve 80% coverage

#### Issue 5: Documentation & Examples
- [ ] Create API documentation
- [ ] Write migration guide from v1.0
- [ ] Create plugin development guide
- [ ] Add usage examples
- [ ] Update README with badges and status

#### Issue 6: Final Validation
- [ ] Run full test suite after fixes
- [ ] Verify 80% overall coverage achieved
- [ ] Run performance benchmarks
- [ ] Cross-platform validation
- [ ] Security audit

---

## 📊 Test Coverage Summary

| Component | Current | Target | Gap | Priority |
|-----------|---------|--------|-----|----------|
| **Core** | 99% | 100% | 1% | Low |
| **Models** | 95% | 100% | 5% | Low |
| **Browser Detector** | 0% | 80% | 80% | **CRITICAL** |
| **Network Detector** | 0% | 80% | 80% | High |
| **HAR Parser** | 10% | 80% | 70% | High |
| **Mitmproxy Parser** | 11% | 80% | 69% | High |
| **Overall** | 48% | 80% | 32% | - |

---

## 🚀 Execution Plan

### Week 1: Critical Fixes (15-20 hours)
**Day 1-2: Browser Detector Test Fixes**
```bash
# 1. Fix browser detector tests
cd tests/unit
# Update test_detectors_browser.py with correct model usage
pytest test_detectors_browser.py -v

# 2. Verify detector functionality
pytest test_detectors_browser.py --cov=src/netstealth_analyzer/detectors/browser.py
```

**Day 3-4: Network Detector Implementation**
```bash
# Create new test file
touch tests/unit/test_detectors_network.py
# Implement comprehensive tests
pytest test_detectors_network.py -v
```

**Day 5-6: Parser Test Expansion**
```bash
# HAR Parser tests
pytest tests/unit/test_parsers_har.py --cov=src/netstealth_analyzer/parsers/har.py

# Mitmproxy Parser tests  
pytest tests/unit/test_parsers_mitmproxy.py --cov=src/netstealth_analyzer/parsers/mitmproxy.py
```

### Week 2: Documentation & Validation (5-10 hours)
**Day 1-2: Documentation**
- API reference generation
- Migration guide creation
- Example scripts

**Day 3-4: Final Testing**
```bash
# Full test suite
pytest tests/ -v

# Coverage report
pytest --cov=src/netstealth_analyzer --cov-report=html

# Performance benchmark
python benchmark.py
```

---

## 💡 Key Implementation Guidelines

### 1. Model Usage Clarification
- **NetworkTrace**: Contains routing information (hops)
- **NetworkHop**: Individual routing points
- **HttpRequest/HttpResponse**: Separate models for HTTP data
- **ConnectionInfo**: Network connection details

### 2. Testing Best Practices
```python
# Use fixtures for common test data
@pytest.fixture
def sample_network_trace():
    return NetworkTrace(
        hops=[
            NetworkHop(
                hop_number=1,
                actor="client",
                actor_name="Test Client",
                incoming_ip="192.168.1.1",
                outgoing_ip="10.0.0.1"
            )
        ]
    )

# Test async methods properly
async def test_async_detection():
    detector = BrowserDetector()
    result = await detector.detect(context)
    assert result.issues_found
```

### 3. Common Pitfalls to Avoid
- Don't mix NetworkTrace with HTTP models
- Use metadata dict for additional information
- Ensure all NetworkHop instances have required fields
- Test with realistic data structures

---

## 🎯 Success Criteria

### Immediate Goals (Week 1)
✅ All tests passing (750+ tests)  
✅ Browser detector tests fixed  
✅ Network detector implemented  
✅ Parser coverage improved  

### Final Goals (Week 2)
✅ 80% overall test coverage  
✅ Complete documentation  
✅ Performance benchmarks met  
✅ Ready for production release  

---

## 🛠️ Quick Commands Reference

```bash
# Run specific test file
pytest tests/unit/test_detectors_browser.py -v

# Check coverage for specific module
pytest --cov=src/netstealth_analyzer/detectors/browser.py tests/

# Run all tests with coverage
pytest --cov=src/netstealth_analyzer --cov-report=html

# Format code
black src/ tests/
ruff check src/ tests/

# Type checking
mypy src/

# Build project
poetry build

# Run in development
poetry shell
python -m netstealth_analyzer
```

---

## 📞 Support & Resources

- **GitHub Repository**: https://github.com/r4d4m4n71s/netstealth-analyzer.git
- **Python 3.13 Docs**: https://docs.python.org/3.13/
- **Asyncio Guide**: https://docs.python.org/3/library/asyncio.html
- **Pydantic v2**: https://docs.pydantic.dev/latest/

---

**Last Updated**: September 17, 2025  
**Next Review**: After Week 1 implementation
