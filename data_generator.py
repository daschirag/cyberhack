#!/usr/bin/env python3
"""
Data Generator for Cybersecurity Anomaly Detection Demo
Creates realistic streaming data with configurable anomaly rates
"""

import json
import time
import os
import random
from datetime import datetime, timedelta
from typing import Dict, List
import argparse
import threading
from pathlib import Path
import tempfile

class CyberSecurityDataGenerator:
    def __init__(self, anomaly_rate=0.8):
        self.anomaly_rate = anomaly_rate
        self.running = False
        
        # Data directories
        self.base_dir = "./data"
        self.login_dir = os.path.join(self.base_dir, "login_stream")
        self.network_dir = os.path.join(self.base_dir, "network_stream") 
        self.file_dir = os.path.join(self.base_dir, "file_stream")
        
        # Ensure directories exist
        for directory in [self.login_dir, self.network_dir, self.file_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Sample data for realistic generation
        self.usernames = ["john_doe", "jane_smith", "alice_wilson", "bob_jones", "charlie_brown", 
                         "diana_prince", "eve_davis", "frank_miller", "grace_lee", "henry_clark"]
        
        self.normal_locations = ["New York", "London", "San Francisco", "Toronto", "Sydney"]
        self.suspicious_locations = ["Moscow", "Beijing", "Unknown", "Darknet", "TOR_Exit"]
        
        self.normal_ips = ["192.168.1.100", "10.0.0.50", "172.16.1.25", "192.168.100.10"]
        self.suspicious_ips = ["185.220.100.50", "31.13.78.35", "103.251.167.10", "45.142.212.21"]
        
        self.normal_files = ["report.pdf", "document.docx", "presentation.pptx", "image.jpg", "data.xlsx"]
        self.suspicious_files = ["database_backup.sql", "passwords.txt", "customer_data.dump", 
                               "financial_records.zip", "secret_keys.bak"]
        
        self.file_counter = 0

    def safe_write_jsonl(self, directory: str, data: Dict):
        """Safely write JSON to file using atomic operations"""
        try:
            # Create a unique filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"data_{timestamp}.jsonl"
            filepath = os.path.join(directory, filename)
            
            # Use atomic write (write to temp file first, then move)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', 
                                           dir=directory, delete=False) as temp_file:
                # Write single line of valid JSON
                json.dump(data, temp_file, default=str)
                temp_file.write('\n')  # JSONL requires newline
                temp_file.flush()
                os.fsync(temp_file.fileno())  # Force write to disk
                
            # Atomically move temp file to final location
            os.rename(temp_file.name, filepath)
            return True
            
        except Exception as e:
            print(f"Error writing data: {e}")
            # Clean up temp file if it exists
            try:
                os.unlink(temp_file.name)
            except:
                pass
            return False

    def generate_login_event(self) -> Dict:
        """Generate a realistic login event"""
        is_anomaly = random.random() < self.anomaly_rate
        
        # Choose user and basic details
        username = random.choice(self.usernames)
        
        if is_anomaly:
            # Create suspicious login
            location = random.choice(self.suspicious_locations)
            ip_address = random.choice(self.suspicious_ips)
            
            # Anomalous time (late night or very early morning)
            if random.random() < 0.5:
                hour = random.randint(23, 23)  # 11 PM
                minute = random.randint(0, 59)
            else:
                hour = random.randint(1, 4)  # 1-4 AM
                minute = random.randint(0, 59)
        else:
            # Normal login
            location = random.choice(self.normal_locations)
            ip_address = random.choice(self.normal_ips)
            hour = random.randint(8, 18)  # Business hours
            minute = random.randint(0, 59)
        
        # Create timestamp
        now = datetime.now().replace(hour=hour, minute=minute, second=random.randint(0, 59))
        timestamp = now.isoformat() + "Z"
        
        return {
            "username": username,
            "location": location,
            "timestamp": timestamp,
            "ip_address": ip_address
        }

    def generate_network_event(self) -> Dict:
        """Generate a realistic network traffic event"""
        is_anomaly = random.random() < self.anomaly_rate
        
        now = datetime.now()
        timestamp = now.isoformat() + "Z"
        source_ip = random.choice(self.normal_ips + self.suspicious_ips)
        
        if is_anomaly:
            # Traffic spike
            requests_per_minute = random.randint(1000, 5000)
        else:
            # Normal traffic
            requests_per_minute = random.randint(50, 200)
        
        return {
            "timestamp": timestamp,
            "requests_per_minute": requests_per_minute,
            "source_ip": source_ip
        }

    def generate_file_event(self) -> Dict:
        """Generate a realistic file transfer event"""
        is_anomaly = random.random() < self.anomaly_rate
        
        username = random.choice(self.usernames)
        operation = random.choice(["upload", "download", "access"])
        now = datetime.now()
        timestamp = now.isoformat() + "Z"
        
        if is_anomaly:
            # Suspicious file transfer
            filename = random.choice(self.suspicious_files)
            file_size_mb = random.uniform(100, 1000)  # Large file
        else:
            # Normal file transfer
            filename = random.choice(self.normal_files)
            file_size_mb = random.uniform(1, 50)  # Normal size
        
        return {
            "username": username,
            "timestamp": timestamp,
            "file_size_mb": round(file_size_mb, 2),
            "operation": operation,
            "filename": filename
        }

    def generate_data_continuously(self):
        """Generate streaming data continuously"""
        print(f"🎯 Starting data generation (Anomaly rate: {self.anomaly_rate*100}%)")
        print(f"📁 Output directories:")
        print(f"   Login: {self.login_dir}")
        print(f"   Network: {self.network_dir}")
        print(f"   File: {self.file_dir}")
        
        while self.running:
            try:
                # Generate login event
                login_event = self.generate_login_event()
                if self.safe_write_jsonl(self.login_dir, login_event):
                    print(f"✅ Login: {login_event['username']} from {login_event['location']}")
                
                # Generate network event  
                network_event = self.generate_network_event()
                if self.safe_write_jsonl(self.network_dir, network_event):
                    rpm = network_event['requests_per_minute']
                    indicator = "🚨" if rpm > 500 else "📊"
                    print(f"{indicator} Network: {rpm} RPM from {network_event['source_ip']}")
                
                # Generate file event
                file_event = self.generate_file_event()
                if self.safe_write_jsonl(self.file_dir, file_event):
                    size = file_event['file_size_mb']
                    indicator = "🚨" if size > 100 else "📄"
                    print(f"{indicator} File: {file_event['username']} {file_event['operation']} {file_event['filename']} ({size}MB)")
                
                # Wait before next generation
                time.sleep(random.uniform(1, 3))  # 1-3 seconds between events
                
            except Exception as e:
                print(f"❌ Error generating data: {e}")
                time.sleep(1)

    def start(self):
        """Start the data generator"""
        self.running = True
        self.generate_data_continuously()

    def stop(self):
        """Stop the data generator"""
        self.running = False

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Data Generator")
    parser.add_argument("--mode", choices=["stream"], default="stream", help="Generation mode")
    parser.add_argument("--anomaly-rate", type=float, default=0.2, help="Rate of anomalies (0.0-1.0)")
    
    args = parser.parse_args()
    
    generator = CyberSecurityDataGenerator(anomaly_rate=args.anomaly_rate)
    
    try:
        print("🚀 CyberSecurity Data Generator Starting...")
        print(f"⚙️  Mode: {args.mode}")
        print(f"📊 Anomaly Rate: {args.anomaly_rate*100}%")
        print("Press Ctrl+C to stop")
        print("=" * 50)
        
        generator.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Stopping data generator...")
        generator.stop()
        print("✅ Data generator stopped")

if __name__ == "__main__":
    main()
