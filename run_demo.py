#!/usr/bin/env python3
"""
Simple Demo Runner for Real-Time Anomaly Detection System
Fixed version that works with test_generator.py
"""

import subprocess
import time
import sys
import os
import signal
from pathlib import Path

# Store processes globally for cleanup
processes = []

def cleanup(signum=None, frame=None):
    """Clean shutdown of all processes"""
    print("\n\n🛑 Stopping all components...")
    for process in processes:
        try:
            process.terminate()
            print(f"  ✓ Stopped process {process.pid}")
        except:
            pass
    print("✅ Demo stopped successfully")
    sys.exit(0)

def check_dependencies():
    """Check if all required packages are installed"""
    required = ['pathway', 'pandas', 'numpy', 'streamlit', 'plotly', 'requests']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        print(f"Please run: pip install {' '.join(missing)}")
        return False
    
    print("✅ All dependencies are installed!")
    return True

def setup_directories():
    """Create necessary directories"""
    dirs = ['./data/login_stream', './data/network_stream', './data/file_stream', './output']
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    
    # Clean old files
    for d in dirs:
        for file in Path(d).glob('*.csv'):
            file.unlink()
        for file in Path(d).glob('*.jsonl'):
            file.unlink()

def main():
    """Main demo runner"""
    print("🛡  Real-Time Anomaly Detection System Demo")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Setup signal handler for clean shutdown
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    # Setup directories
    setup_directories()
    
    print("🎮 Starting demo components...")
    print("Press Ctrl+C to stop all components\n")
    
    try:
        # Start anomaly detection system
        print("🚀 Starting anomaly detection system...")
        anomaly_process = subprocess.Popen(
            ["python", "anomaly_detection.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(anomaly_process)
        time.sleep(3)  # Give it time to start
        
        # Start dashboard
        print("📊 Starting dashboard...")
        dashboard_process = subprocess.Popen(
            ["streamlit", "run", "dashboard.py", "--server.headless", "true", "--server.address", "localhost"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(dashboard_process)
        time.sleep(3)  # Give it time to start
        
        # Generate test data based on argument
        if len(sys.argv) > 1 and sys.argv[1] == '--attack':
            print("📡 Starting data generator in ATTACK mode...")
            # Use test_generator.py with --attack flag
            generator_process = subprocess.Popen(
                ["python", "data_generator.py", "--attack"]
            )
        elif len(sys.argv) > 1 and sys.argv[1] == '--normal':
            print("📡 Starting data generator in NORMAL mode...")
            generator_process = subprocess.Popen(
                ["python", "data_generator.py", "--normal"]
            )
        else:
            print("📡 Starting interactive test sequence...")
            print("\nFollow the prompts in the test generator window")
            generator_process = subprocess.Popen(
                ["python", "data_generator.py"]
            )
        
        processes.append(generator_process)
        
        print("\n✅ All components started!")
        print("📊 Dashboard: http://localhost:8501")
        print("🔍 Watch the terminal for real-time alerts")
        print("\nPress Ctrl+C to stop...")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            # Check if any process has died
            for p in processes:
                if p.poll() is not None:
                    print(f"⚠  Process {p.pid} stopped unexpectedly")
                    
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"❌ Error: {e}")
        cleanup()

if __name__ == "__main__":
    main()