#!/usr/bin/env python3
"""
Coverage Analysis Script for NetStealth Analyzer v2.0

This script analyzes test coverage data to determine if the 80% core functionality 
coverage target has been achieved, distinguishing between core and extended functionality.
"""

def analyze_core_coverage():
    """Analyze coverage for core functionality components."""
    
    print('🔍 DETAILED CORE FUNCTIONALITY COVERAGE ANALYSIS')
    print('=' * 60)
    print()

    # Define core vs extended functionality based on architecture importance
    core_components = {
        'Core Infrastructure': {
            'src/netstealth_analyzer/core/interfaces.py': 97,
            'src/netstealth_analyzer/core/events.py': 49,
            'src/netstealth_analyzer/core/errors.py': 35,
        },
        'Data Models': {
            'src/netstealth_analyzer/models/enums.py': 100,
            'src/netstealth_analyzer/models/issues.py': 58,
            'src/netstealth_analyzer/models/network.py': 54,
            'src/netstealth_analyzer/models/results.py': 59,
        },
        'Reporting System': {
            'src/netstealth_analyzer/reporting/reporter.py': 96,
            'src/netstealth_analyzer/reporting/formats.py': 82,
        },
        'Plugin System': {
            'src/netstealth_analyzer/plugins/base.py': 89,
            'src/netstealth_analyzer/plugins/registry.py': 67,
            'src/netstealth_analyzer/plugins/sandbox.py': 35,
            'src/netstealth_analyzer/plugins/loader.py': 16,
        },
        'Configuration & Compatibility': {
            'src/netstealth_analyzer/config.py': 39,
            'src/netstealth_analyzer/compatibility.py': 46,
        }
    }

    extended_components = {
        'Parsers (Implementation)': {
            'src/netstealth_analyzer/parsers/har.py': 10,
            'src/netstealth_analyzer/parsers/mitmproxy.py': 10,
            'src/netstealth_analyzer/parsers/browser.py': 10,
            'src/netstealth_analyzer/parsers/poc.py': 9,
        },
        'Detectors (Implementation)': {
            'src/netstealth_analyzer/detectors/tls.py': 0,
            'src/netstealth_analyzer/detectors/proxy.py': 0,
            'src/netstealth_analyzer/detectors/browser.py': 0,
            'src/netstealth_analyzer/detectors/network.py': 0,
        },
        'Orchestration (High-level)': {
            'src/netstealth_analyzer/analyzer.py': 13,
            'src/netstealth_analyzer/builder.py': 13,
            'src/netstealth_analyzer/core/pipeline.py': 16,
        }
    }

    print('📊 CORE FUNCTIONALITY COVERAGE ANALYSIS')
    print('-' * 50)

    total_core_coverage = 0
    total_core_components = 0
    components_above_80 = 0
    components_below_80 = 0
    gap_components = []

    for category, components in core_components.items():
        print(f'\n🔧 {category}')
        print('  ' + '-' * 40)
        category_coverage = 0
        category_count = 0
        
        for component, coverage in components.items():
            status = '✅' if coverage >= 80 else '❌'
            print(f'  {status} {component.split("/")[-1]}: {coverage}%')
            
            if coverage >= 80:
                components_above_80 += 1
            else:
                components_below_80 += 1
                gap_components.append((component, coverage))
                
            category_coverage += coverage
            category_count += 1
            total_core_coverage += coverage
            total_core_components += 1
        
        avg_coverage = category_coverage / category_count if category_count > 0 else 0
        category_status = '✅' if avg_coverage >= 80 else '❌'
        print(f'  {category_status} Category Average: {avg_coverage:.1f}%')

    print('\n' + '=' * 60)
    overall_core_coverage = total_core_coverage / total_core_components if total_core_components > 0 else 0
    target_status = '✅ TARGET MET' if overall_core_coverage >= 80 else '❌ BELOW TARGET'

    print(f'📈 CORE FUNCTIONALITY SUMMARY')
    print(f'   Overall Core Coverage: {overall_core_coverage:.1f}%')
    print(f'   Target Coverage: 80%')
    print(f'   Status: {target_status}')
    print(f'   Components ≥80%: {components_above_80}')
    print(f'   Components <80%: {components_below_80}')
    print()

    print('🎯 COVERAGE TARGET ANALYSIS')
    print('-' * 30)
    if overall_core_coverage >= 80:
        print('✅ SUCCESS: Core functionality coverage target achieved!')
        print('🏆 The project meets the 80% core coverage requirement.')
    else:
        print('❌ GAP IDENTIFIED: Core functionality below 80% target')
        print(f'   Current: {overall_core_coverage:.1f}%')
        print(f'   Gap: {80 - overall_core_coverage:.1f}%')
        print()
        print('📝 COMPONENTS NEEDING ADDITIONAL TESTS:')
        for component, coverage in gap_components:
            gap = 80 - coverage
            print(f'   • {component.split("/")[-1]}: {coverage}% (need +{gap}%)')

    print()
    print('📋 EXTENDED FUNCTIONALITY (Not counted toward core 80%)')
    print('-' * 55)
    for category, components in extended_components.items():
        avg = sum(components.values()) / len(components)
        print(f'ℹ️  {category}: {avg:.1f}% average (implementation-specific)')
    
    print('\n' + '=' * 60)
    print('💡 RECOMMENDATIONS')
    print('-' * 20)
    
    if overall_core_coverage < 80:
        print('🔧 PRIORITY ACTIONS TO REACH 80% TARGET:')
        print('   1. Add EventBus system tests (events.py: 49% → 80%)')
        print('   2. Add Error handling tests (errors.py: 35% → 80%)')
        print('   3. Add Data Model tests (issues.py, network.py, results.py)')
        print('   4. Add Configuration tests (config.py: 39% → 80%)')
        print('   5. Add Plugin loading tests (loader.py: 16% → 80%)')
        print()
        print('📊 IMPACT ANALYSIS:')
        needed_coverage = 80 * total_core_components - total_core_coverage
        print(f'   Need {needed_coverage:.1f} percentage points across {total_core_components} components')
        print(f'   Focus on lowest coverage components for maximum impact')
    else:
        print('🎉 EXCELLENT: Core functionality coverage target achieved!')
        print('   Consider adding integration tests for end-to-end validation')
    
    return overall_core_coverage >= 80, overall_core_coverage, gap_components


def main():
    """Main function to run coverage analysis."""
    print("NetStealth Analyzer v2.0 - Coverage Analysis")
    print("=" * 50)
    print()
    
    target_met, coverage, gaps = analyze_core_coverage()
    
    print(f'\n🎯 FINAL VERDICT')
    print(f'   Core Coverage: {coverage:.1f}%')
    print(f'   Target Met: {"YES" if target_met else "NO"}')
    print(f'   Components Below 80%: {len(gaps)}')
    
    return 0 if target_met else 1


if __name__ == "__main__":
    exit(main())
