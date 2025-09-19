#!/usr/bin/env python3
"""
Hackathon Demo Starter Script
Starts all components of the cybersecurity anomaly detection system
"""

import subprocess
import sys
import time
import os
import signal
import threading
from pathlib import Path

class HackathonDemo:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def start_backend(self):
        """Start the FastAPI backend"""
        print("🚀 Starting FastAPI backend...")
        try:
            # Change to backend directory
            backend_dir = Path("backend")
            if not backend_dir.exists():
                print("❌ Backend directory not found!")
                return None
                
            # Start the backend
            process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("✅ Backend started on http://localhost:8000")
            return process
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return None
    
    def start_frontend(self):
        """Start the React frontend"""
        print("🎨 Starting React frontend...")
        try:
            frontend_dir = Path("frontend")
            if not frontend_dir.exists():
                print("❌ Frontend directory not found!")
                return None
                
            # Check if node_modules exists
            if not (frontend_dir / "node_modules").exists():
                print("📦 Installing frontend dependencies...")
                subprocess.run(["npm", "install"], cwd=frontend_dir, check=True)
            
            # Start the frontend
            process = subprocess.Popen(
                ["npm", "start"],
                cwd=frontend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("✅ Frontend started on http://localhost:3000")
            return process
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return None
    
    def start_anomaly_detection(self):
        """Start the anomaly detection system"""
        print("🛡️ Starting anomaly detection system...")
        try:
            process = subprocess.Popen(
                [sys.executable, "anomaly_detection.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("✅ Anomaly detection system started")
            return process
        except Exception as e:
            print(f"❌ Failed to start anomaly detection: {e}")
            return None
    
    def start_data_generator(self):
        """Start the data generator for demo"""
        print("📊 Starting data generator...")
        try:
            process = subprocess.Popen(
                [sys.executable, "data_generator.py", "--mode", "stream", "--anomaly-rate", "0.2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("✅ Data generator started")
            return process
        except Exception as e:
            print(f"❌ Failed to start data generator: {e}")
            return None
    
    def monitor_processes(self):
        """Monitor all processes and restart if needed"""
        while self.running:
            time.sleep(5)
            for i, process in enumerate(self.processes):
                if process and process.poll() is not None:
                    print(f"⚠️ Process {i} stopped unexpectedly")
                    # Could add restart logic here
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n🛑 Shutting down hackathon demo...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up all processes"""
        for process in self.processes:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        print("✅ All processes stopped")
    
    def run(self):
        """Run the complete hackathon demo"""
        print("🎯 Starting CyberShield Hackathon Demo")
        print("=" * 50)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Create necessary directories
        os.makedirs("./output", exist_ok=True)
        os.makedirs("./data/login_stream", exist_ok=True)
        os.makedirs("./data/network_stream", exist_ok=True)
        os.makedirs("./data/file_stream", exist_ok=True)
        
        # Start all components
        backend_process = self.start_backend()
        if backend_process:
            self.processes.append(backend_process)
            time.sleep(3)  # Give backend time to start
        
        frontend_process = self.start_frontend()
        if frontend_process:
            self.processes.append(frontend_process)
            time.sleep(3)  # Give frontend time to start
        
        anomaly_process = self.start_anomaly_detection()
        if anomaly_process:
            self.processes.append(anomaly_process)
            time.sleep(2)
        
        data_process = self.start_data_generator()
        if data_process:
            self.processes.append(data_process)
        
        print("\n🎉 Hackathon Demo is running!")
        print("=" * 50)
        print("📱 Frontend: http://localhost:3000")
        print("🔧 Backend API: http://localhost:8000")
        print("📊 API Docs: http://localhost:8000/docs")
        print("🛡️ Anomaly Detection: Running")
        print("📈 Data Generator: Running")
        print("\nPress Ctrl+C to stop all services")
        print("=" * 50)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        monitor_thread.start()
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    demo = HackathonDemo()
    demo.run()
