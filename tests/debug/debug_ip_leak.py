#!/usr/bin/env python3

from tests.unit.test_actors_proxy import TestProxyActor

def debug_ip_leak():
    test = TestProxyActor()
    test.setup_method()
    
    # Create trace with IP leak response
    trace = test.create_mock_trace_with_headers(
        [], 
        response_body="Real IP address detected: 192.168.1.1"
    )
    
    # Try to identify
    identification = test.proxy_actor.identify(trace)
    
    if identification:
        print('Identification found!')
        print(f'Actor type: {identification.actor_type}')
        print(f'Confidence: {identification.confidence}')
        print(f'Patterns matched: {identification.patterns_matched}')
        print()
        
        for i, pattern in enumerate(identification.patterns_matched):
            print(f'Pattern {i+1}: "{pattern}"')
            print(f'  Contains "ip": {"ip" in pattern.lower()}')
            print(f'  Contains "leak": {"leak" in pattern.lower()}')
            print(f'  Contains "ip.*leak": {"ip.*leak" in pattern.lower()}')
            print(f'  Regex match ip.*leak: {bool(__import__("re").search(r"ip.*leak", pattern.lower()))}')
            print()
    else:
        print('No identification found')
        
    # Let's also check what patterns are available
    print("Available patterns:")
    for i, pattern in enumerate(test.proxy_actor.patterns):
        print(f'{i+1}. {pattern.__class__.__name__}: {pattern.description}')
        if hasattr(pattern, 'pattern'):
            print(f'   Regex: {pattern.pattern.pattern}')

if __name__ == "__main__":
    debug_ip_leak()
