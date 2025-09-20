# NetStealth Analyzer - Sample Data

This directory contains sample data files for testing and demonstrating the NetStealth Analyzer functionality.

## Overview

The sample data is designed to showcase various security issues and network patterns that the NetStealth Analyzer can detect, including:

- Browser automation detection
- IP address leakage  
- Insecure connections
- Sensitive data exposure  
- Third-party tracking
- Fingerprinting attempts
- Geographic routing inconsistencies
- Proxy chain detection
- Datacenter IP detection

## Available Sample Files

### `sample_session.har` (Basic Issues Demo)
**Format**: HAR (HTTP Archive Format) v1.2  
**Size**: ~8KB  
**Purpose**: Basic demonstration with moderate security issues

**Contains**:
- 3 HTTP/HTTPS requests demonstrating common security issues
- Browser automation detection patterns
- Third-party tracking scenarios
- Debug information leakage

**Security Issues Demonstrated**:
- Browser automation detection (HeadlessChrome user agent)
- IP address leakage in headers (X-Forwarded-For)
- Third-party tracking with user data
- Insecure HTTP connections for tracking
- Debug mode enabled with sensitive information
- Sensitive data in query parameters and POST bodies

**Expected Results**: **3-5 issues found** (Score: 60-80/100)
- Risk Level: MEDIUM
- Issues: Browser automation, tracking, debug leakage, IP exposure

### `sample_clean_session.har` (Clean Scenario)
**Format**: HAR (HTTP Archive Format) v1.2  
**Size**: ~3KB  
**Purpose**: Demonstrates analyzer behavior with clean, secure traffic

**Contains**:
- 2 HTTPS requests to legitimate services
- Proper security headers
- No automation signatures
- Clean network routing

**Expected Results**: **0 issues found** (Score: 100/100)
- Perfect security score
- No violations detected
- Clean network traces

### `sample_high_risk_session.har` (Comprehensive High-Risk Scenario) ⚠️
**Format**: HAR (HTTP Archive Format) v1.2  
**Size**: ~25KB  
**Purpose**: **Comprehensive testing scenario covering maximum security issues**

**Contains**: 
- **4 HTTP/HTTPS requests** demonstrating extensive security violations
- **Multi-vector attack patterns** for comprehensive detection testing
- **Complete coverage of detection categories**

#### Security Issues Demonstrated:

**🚨 CRITICAL Issues:**
- Browser automation detection (HeadlessChrome, webdriver headers)
- Insecure HTTP connections with sensitive data (PII, credentials)
- Sensitive data exposure (SSN, credit cards, API keys)
- Debug mode enabled with internal information leakage
- Admin token exposure in URLs

**🔥 HIGH Issues:**
- Complex proxy chain detection (4-hop proxy chain)
- IP address leakage in multiple headers (X-Forwarded-For, Via, X-Real-IP)
- Datacenter IP detection with hosting provider identification
- VPN detection and geolocation inconsistencies
- Rate limit bypass attempts

**⚠️ MEDIUM Issues:**
- Advanced fingerprinting scripts (Canvas, WebGL, Audio, WebRTC)
- Third-party tracking with comprehensive data collection
- Cross-site data sharing without consent
- Behavioral analysis showing automation patterns
- Security header violations

**ℹ️ LOW Issues:**
- Compliance violations (GDPR, CCPA, PCI-DSS, HIPAA)
- Cookie security issues (SameSite=None, insecure flags)
- Debug headers and development artifacts
- Timing analysis revealing automation

#### Network Analysis Features:
- **Multi-hop proxy chains**: 4-level proxy routing
- **Datacenter detection**: AS54113 Datacenter Solutions LLC
- **Geographic analysis**: Virginia datacenter with routing inconsistencies
- **Protocol analysis**: Mixed HTTP/HTTPS with security implications
- **Timing patterns**: Automated request timing signatures

**Expected Results**: **15-25+ issues found** (Score: 5-20/100)
- Risk Level: **CRITICAL**
- Multiple high-severity security violations
- Complex network routing patterns
- Comprehensive automation detection

### `sample_proxy.log`
**Format**: Custom proxy log format  
**Size**: ~6KB  
**Description**: Mitmproxy session log with detailed security analysis

**Contains**:
- Proxy server configuration and startup logs
- Request/response interception with security annotations
- Real-time security issue detection
- Geographic and routing analysis
- Risk assessment calculations

## Usage Examples

### Basic Analysis (simple_analysis.py)

```bash
cd examples/basic_usage
python simple_analysis.py
```

Uses: `../sample_data/sample_session.har` (basic clean scenario)

### Multiple Files Analysis (multiple_files.py)

```bash
cd examples/basic_usage
python multiple_files.py
```

Uses: `../sample_data/sample_session.har` + `../sample_data/sample_proxy.log`

### Streaming Analysis (streaming_analysis.py)

```bash
cd examples/basic_usage
python streaming_analysis.py  
```

Uses: `../sample_data/sample_session.har` (streaming mode)

### Advanced Proxy Security Audit (proxy_audit.py)

```bash
cd examples/advanced_workflows
python proxy_audit.py
```

Uses: `../sample_data/sample_session.har` + `../sample_data/sample_proxy.log`

## Testing Different Scenarios

### Scenario 1: Clean Traffic Testing
**File**: `sample_clean_session.har`
**Purpose**: Test analyzer with legitimate, secure traffic
**Expected**: 0 issues, perfect score
**Use Case**: Baseline testing, false positive validation

### Scenario 2: Basic Issues Testing  
**File**: `sample_session.har` (original)
**Purpose**: Standard functionality testing
**Expected**: 0 issues currently (clean data)
**Use Case**: Basic example demonstrations

### Scenario 3: Comprehensive High-Risk Testing ⚠️
**File**: `sample_high_risk_session.har`  
**Purpose**: **Maximum security issue coverage**
**Expected**: 15-25+ critical/high severity issues
**Use Case**: Algorithm testing, edge case validation, comprehensive detection testing

To test with high-risk data, modify examples to use:
```python
# Instead of:
.with_logs("../sample_data/sample_session.har")

# Use:
.with_logs("../sample_data/sample_high_risk_session.har")
```

## Sample Data Security Coverage Matrix

| Category | Clean Session | Basic Session | High-Risk Session |
|----------|--------------|---------------|-------------------|
| Browser Automation | ❌ None | ✅ HeadlessChrome detection | ✅ Comprehensive |
| Proxy Detection | ❌ None | ❌ None | ✅ Multi-hop chains |
| IP Leakage | ❌ None | ✅ X-Forwarded-For header | ✅ Multiple headers |
| Fingerprinting | ❌ None | ❌ None | ✅ Multi-vector |
| Data Exposure | ❌ None | ✅ Phone, email, IP in responses | ✅ PII/credentials |
| Third-party Tracking | ❌ None | ✅ HTTP tracking pixels | ✅ Comprehensive |
| Network Anomalies | ❌ None | ❌ None | ✅ Geographic inconsistencies |
| Compliance Issues | ❌ None | ❌ None | ✅ Multiple violations |
| Debug Leakage | ❌ None | ✅ Debug mode enabled | ✅ Internal information |
| Security Headers | ✅ Proper | ⚠️ Mixed (some proper) | ❌ Multiple violations |

## Expected Analysis Results by File

### `sample_clean_session.har`
```
🎯 Analysis Results:
   Overall Score: 100/100
   Risk Level: MINIMAL  
   Total Issues: 0
   Security Assessment: PASSED
```

### `sample_session.har` (Basic Issues Demo)
```
🎯 Analysis Results:
   Overall Score: 60-80/100
   Risk Level: MEDIUM
   Total Issues: 3-5
   Medium Issues: 2-3
   Low Issues: 1-2
   Security Assessment: WARNING
   Issues: Browser automation, IP leakage, tracking, debug exposure
```

### `sample_high_risk_session.har` ⚠️
```
🎯 Analysis Results:
   Overall Score: 5-20/100
   Risk Level: CRITICAL
   Total Issues: 15-25+
   Critical Issues: 5-8
   High Issues: 4-7
   Medium Issues: 3-6
   Low Issues: 3-5
   Security Assessment: FAILED
   Recommended Action: BLOCK
```

## File Structure Details

### HAR File Format
All HAR files follow HTTP Archive 1.2 specification:
```json
{
  "log": {
    "version": "1.2",
    "creator": {"name": "NetStealth Test Data Generator", "version": "2.0.0"},
    "entries": [...]
  }
}
```

### High-Risk Session Breakdown

#### Entry 1: Sensitive API Request
- **URL**: `http://target-service.com/api/user/profile` (HTTP, not HTTPS!)
- **Issues**: Automation headers, proxy chains, sensitive data exposure, admin tokens
- **Headers**: webdriver=true, selenium-version, proxy chains via X-Forwarded-For
- **Response**: PII data (SSN, credit cards, internal IDs)

#### Entry 2: Advanced Fingerprinting
- **URL**: `https://fingerprint.tracking-service.com/advanced-collect.js`
- **Issues**: Multi-vector fingerprinting, automation detection, tracking
- **Methods**: Canvas, WebGL, Audio, WebRTC, behavioral analysis
- **Response**: JavaScript code for comprehensive browser fingerprinting

#### Entry 3: Comprehensive Tracking
- **URL**: `http://analytics.third-party-tracker.net/comprehensive-event`  
- **Issues**: Third-party tracking, compliance violations, data monetization
- **Data**: Complete user profile, behavioral analysis, risk assessment
- **Violations**: GDPR, CCPA, PCI-DSS, HIPAA compliance issues

#### Entry 4: IP Detection Service
- **URL**: `http://whatismyip.detect-proxy-service.net/comprehensive-check`
- **Issues**: Datacenter IP detection, proxy/VPN detection, threat analysis  
- **Detection**: Confirmed datacenter IP, proxy chains, high threat score
- **Response**: Complete geographic and ISP analysis

## Data Safety & Privacy

### Fictional Data Only
- All domains use example.com or fictional services
- IP addresses use RFC 5737 documentation ranges (198.51.100.x, 203.0.113.x, 192.0.2.x)
- Personal data is completely fictional (John Doe, fake SSNs, test credit cards)
- No real credentials or sensitive information

### Test Environment Only
- **⚠️ NEVER use in production environments**
- Sample data contains intentional security vulnerabilities
- High-risk data designed to trigger maximum security alerts
- Files are for testing and demonstration purposes only

## Integration with Examples

### Default File Usage
Most examples use the basic clean data by default:
```python
# Default path in examples
"../sample_data/sample_session.har"
```

### Testing High-Risk Scenarios
To test comprehensive detection, modify examples:
```python
# For maximum security issue coverage
.with_logs("../sample_data/sample_high_risk_session.har")
```

### Multiple File Analysis
Advanced examples use multiple files:
```python
.with_logs(
    "../sample_data/sample_session.har",
    "../sample_data/sample_proxy.log"  
)
```

## Troubleshooting

### Common Issues

**No Issues Found with High-Risk Data**:
- Verify you're using `sample_high_risk_session.har`
- Check detector configuration: `.with_detectors("proxy", "browser", "network")`
- Enable debug logging to see detection process

**File Not Found Errors**:
- Run examples from correct directory: `examples/basic_usage/` or `examples/advanced_workflows/`
- Verify sample_data directory exists in examples/

**JSON Parse Errors**:
- All sample files are validated JSON
- Check file wasn't corrupted during download/transfer

### Performance Notes

**High-Risk Data File**:
- Contains extensive data for comprehensive testing
- May take longer to process than basic samples
- Designed to stress-test detection algorithms
- Perfect for validation and edge case testing

## Data Generation Information

**Generated**: January 2025  
**NetStealth Version**: 2.0+  
**HAR Specification**: 1.2  
**Coverage**: Comprehensive security vulnerability testing

The sample data is designed to provide complete test coverage for all NetStealth Analyzer detection capabilities, from clean baseline testing to comprehensive high-risk scenario validation.
