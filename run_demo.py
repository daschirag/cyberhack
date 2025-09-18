#!/usr/bin/env python3
"""
Demo runner script for the Real-Time Anomaly Detection System
This script helps you quickly start all components for demonstration
"""

import subprocess
import sys
import time
import os
from pathlib import Path

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = ['streamlit', 'plotly', 'pandas', 'pathway']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("📦 Installing missing packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed!")
    else:
        print("✅ All dependencies are installed!")

def start_detection_system():
    """Start the anomaly detection system"""
    print("🚀 Starting anomaly detection system...")
    return subprocess.Popen([
        sys.executable, "src/anomaly_detection.py"
    ], cwd=Path(__file__).parent)

def start_dashboard():
    """Start the Streamlit dashboard"""
    print("📊 Starting dashboard...")
    return subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "src/dashboard.py"
    ], cwd=Path(__file__).parent)

def start_data_generator(mode="attack"):
    """Start the data generator"""
    print(f"📡 Starting data generator in {mode} mode...")
    return subprocess.Popen([
        sys.executable, "src/data_generator.py", "--mode", mode, "--duration", "10"
    ], cwd=Path(__file__).parent)

def main():
    """Main demo function"""
    print("🛡️ Real-Time Anomaly Detection System Demo")
    print("=" * 50)
    
    # Check dependencies
    check_dependencies()
    
    print("\n🎮 Starting demo components...")
    print("Press Ctrl+C to stop all components")
    
    processes = []
    
    try:
        # Start detection system
        detection_process = start_detection_system()
        processes.append(detection_process)
        time.sleep(2)
        
        # Start dashboard
        dashboard_process = start_dashboard()
        processes.append(dashboard_process)
        time.sleep(3)
        
        # Start data generator
        data_process = start_data_generator("attack")
        processes.append(data_process)
        
        print("\n✅ All components started!")
        print("📊 Dashboard: http://localhost:8501")
        print("🔍 Watch the terminal for real-time alerts")
        print("\nPress Ctrl+C to stop...")
        
        # Wait for user to stop
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping all components...")
        
        # Terminate all processes
        for process in processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        print("✅ All components stopped!")

if __name__ == "__main__":
    main()
