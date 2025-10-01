#!/usr/bin/env python3
"""
Test script for open taint tracking analysis
"""

import sys
from pathlib import Path
sys.path.insert(0, '/home/rui/HNP_PHP')

from interactive_analyzer import FrameworkAnalyzer

def test_open_analysis():
    """Test the open analysis functionality"""
    print("🧪 Testing Open Taint Tracking Analysis")
    print("=" * 50)
    
    analyzer = FrameworkAnalyzer()
    
    # Test with Laravel
    framework_name = "Laravel"
    framework_path = "laravel"
    
    print(f"🎯 Testing open analysis on {framework_name}")
    
    try:
        success = analyzer.run_open_analysis(framework_path, framework_name)
        if success:
            print(f"\n✅ Open analysis test completed successfully!")
        else:
            print(f"\n❌ Open analysis test failed!")
        return success
    except Exception as e:
        print(f"\n❌ Error during open analysis test: {e}")
        return False

if __name__ == "__main__":
    success = test_open_analysis()
    sys.exit(0 if success else 1)
