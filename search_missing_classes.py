#!/usr/bin/env python3
"""
Search for existing HttpRequest, HttpResponse, and TimingInfo classes in the codebase.
"""

import os
import sys

def search_classes():
    """Search for target classes in the codebase."""
    target_classes = ['HttpRequest', 'HttpResponse', 'TimingInfo']
    
    print("Searching for missing classes in the codebase...")
    found_classes = {}
    
    for root, dirs, files in os.walk('src'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    for class_name in target_classes:
                        if f'class {class_name}' in content:
                            found_classes[class_name] = filepath
                            print(f'✅ Found {class_name} in {filepath}')
                            # Get the line
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if f'class {class_name}' in line:
                                    print(f'   Line {i+1}: {line.strip()}')
                                    break
                except Exception as e:
                    pass
    
    print(f"\n=== SUMMARY ===")
    for class_name in target_classes:
        if class_name in found_classes:
            print(f"✅ {class_name} exists in {found_classes[class_name]}")
        else:
            print(f"❌ {class_name} NOT FOUND - needs to be created or imported")
    
    # If classes don't exist, suggest where they might belong
    if not found_classes:
        print(f"\n=== SUGGESTION ===")
        print("These classes should likely be:")
        print("1. Added to src/netstealth_analyzer/models/network.py, OR")
        print("2. Created in a separate HTTP models file, OR") 
        print("3. Imported from an external library")
        
        # Check if they're used in HAR parser context
        print("\n=== CONTEXT CHECK ===")
        har_file = 'src/netstealth_analyzer/parsers/har.py'
        if os.path.exists(har_file):
            with open(har_file, 'r') as f:
                har_content = f.read()
            
            if 'HttpRequest' in har_content:
                print("These classes are used in HAR parser - they represent HTTP request/response data")
                print("They should be proper Pydantic models for parsing HTTP traffic from HAR files")

if __name__ == "__main__":
    search_classes()
