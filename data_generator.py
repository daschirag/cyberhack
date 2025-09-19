"""
Security Event Data Generator
Fixed version with --mode support for compatibility
"""

import csv
import json
import random
import time
import os
from datetime import datetime, timedelta
import argparse

class SecurityDataGenerator:
    """Generate realistic security event data with anomalies"""
    
    def __init__(self, anomaly_rate=0.1):
        self.anomaly_rate = anomaly_rate
        
        # Normal patterns
        self.normal_users = ['alice', 'bob', 'charlie', 'diana', 'eve']
        self.normal_locations = ['Chennai', 'Mumbai', 'Delhi', 'Bangalore', 'Pune']
        self.normal_ips = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13', '192.168.1.14']
        
        # Anomalous patterns
        self.suspicious_locations = ['Moscow', 'Beijing', 'Lagos', 'Unknown', 'Tor Exit Node']
        self.suspicious_ips = ['185.220.101.45', '31.13.24.87', '103.251.167.20', '45.142.120.135']
        
        # File patterns
        self.normal_files = [
            ('report.pdf', 2.5), ('presentation.pptx', 8.3), ('data.xlsx', 1.2),
            ('document.docx', 0.8), ('image.png', 3.4), ('code.py', 0.1)
        ]
        self.suspicious_files = [
            ('database_dump.sql', 500.0), ('customer_data.zip', 250.0),
            ('passwords.txt', 150.0), ('financial_records.xlsx', 300.0)
        ]
        
        # Ensure output directories exist
        os.makedirs('./data/login_stream', exist_ok=True)
        os.makedirs('./data/network_stream', exist_ok=True)
        os.makedirs('./data/file_stream', exist_ok=True)
    
    def generate_login_event(self, is_anomaly=False):
        """Generate a login event"""
        timestamp = datetime.now()
        
        if is_anomaly:
            username = random.choice(self.normal_users)
            location = random.choice(self.suspicious_locations)
            ip_address = random.choice(self.suspicious_ips)
            # Make it at odd hours
            timestamp = timestamp.replace(hour=random.choice([2, 3, 4, 23]))
        else:
            username = random.choice(self.normal_users)
            location = random.choice(self.normal_locations)
            ip_address = random.choice(self.normal_ips)
            # Normal hours (9 AM to 6 PM)
            hour = timestamp.hour
            if hour < 9 or hour > 18:
                timestamp = timestamp.replace(hour=random.randint(9, 18))
        
        return {
            'username': username,
            'location': location,
            'timestamp': timestamp.isoformat(),
            'ip_address': ip_address
        }
    
    def generate_network_event(self, is_anomaly=False):
        """Generate network traffic event"""
        timestamp = datetime.now()
        
        if is_anomaly:
            requests_per_minute = random.randint(5000, 50000)
            source_ip = random.choice(self.suspicious_ips)
        else:
            requests_per_minute = random.randint(50, 200)
            source_ip = random.choice(self.normal_ips)
        
        return {
            'timestamp': timestamp.isoformat(),
            'requests_per_minute': requests_per_minute,
            'source_ip': source_ip
        }
    
    def generate_file_event(self, is_anomaly=False):
        """Generate file transfer event"""
        timestamp = datetime.now()
        username = random.choice(self.normal_users)
        
        if is_anomaly:
            filename, size = random.choice(self.suspicious_files)
            file_size_mb = size + random.uniform(-50, 50)
            operation = 'download'
        else:
            filename, size = random.choice(self.normal_files)
            file_size_mb = size + random.uniform(-0.5, 0.5)
            operation = random.choice(['upload', 'download'])
        
        return {
            'username': username,
            'timestamp': timestamp.isoformat(),
            'file_size_mb': max(0.1, file_size_mb),
            'operation': operation,
            'filename': filename
        }
    
    def write_event_to_csv(self, event_type, event_data):
        """Write event to CSV file"""
        if event_type == 'login':
            filepath = f'./data/login_stream/login_{int(time.time()*1000)}.csv'
            fieldnames = ['username', 'location', 'timestamp', 'ip_address']
        elif event_type == 'network':
            filepath = f'./data/network_stream/network_{int(time.time()*1000)}.csv'
            fieldnames = ['timestamp', 'requests_per_minute', 'source_ip']
        elif event_type == 'file':
            filepath = f'./data/file_stream/file_{int(time.time()*1000)}.csv'
            fieldnames = ['username', 'timestamp', 'file_size_mb', 'operation', 'filename']
        else:
            return None
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(event_data)
        
        return filepath
    
    def run_attack_simulation(self, duration=10):
        """Simulate a coordinated attack"""
        print("\n" + "="*60)
        print("SIMULATING COORDINATED ATTACK SCENARIO")
        print("="*60)
        
        # Phase 1: Reconnaissance
        print("\n[Phase 1: Reconnaissance - Suspicious Login Attempts]")
        for i in range(3):
            event = self.generate_login_event(is_anomaly=True)
            self.write_event_to_csv('login', event)
            print(f"  - Suspicious login: {event['username']} from {event['location']}")
            time.sleep(0.5)
        
        # Phase 2: DDoS
        print("\n[Phase 2: DDoS Attack to Distract Security Team]")
        for i in range(5):
            event = self.generate_network_event(is_anomaly=True)
            self.write_event_to_csv('network', event)
            print(f"  - Traffic spike: {event['requests_per_minute']} req/min")
            time.sleep(0.3)
        
        # Phase 3: Data exfiltration
        print("\n[Phase 3: Data Exfiltration Attempt]")
        for i in range(3):
            event = self.generate_file_event(is_anomaly=True)
            self.write_event_to_csv('file', event)
            print(f"  - Large download: {event['filename']} ({event['file_size_mb']:.1f}MB)")
            time.sleep(0.5)
        
        print("\n[Attack simulation complete]")
        print("="*60)
    
    def run_stream_mode(self, interval_seconds=2, duration=None):
        """Generate continuous stream of events"""
        print(f"Starting continuous data stream (interval: {interval_seconds}s)")
        print(f"Anomaly rate: {self.anomaly_rate*100:.1f}%")
        print("Press Ctrl+C to stop\n")
        
        start_time = time.time()
        event_count = 0
        
        try:
            while True:
                # Check duration limit
                if duration and (time.time() - start_time) > duration:
                    break
                
                # Generate 1-3 events per interval
                num_events = random.randint(1, 3)
                
                for _ in range(num_events):
                    event_type = random.choice(['login', 'network', 'file'])
                    is_anomaly = random.random() < self.anomaly_rate
                    
                    if event_type == 'login':
                        event = self.generate_login_event(is_anomaly)
                        self.write_event_to_csv('login', event)
                        status = "🚨 ANOMALY" if is_anomaly else "✓ Normal"
                        print(f"[{status}] Login: {event['username']} from {event['location']}")
                    
                    elif event_type == 'network':
                        event = self.generate_network_event(is_anomaly)
                        self.write_event_to_csv('network', event)
                        status = "🚨 ANOMALY" if is_anomaly else "✓ Normal"
                        print(f"[{status}] Network: {event['requests_per_minute']} req/min")
                    
                    elif event_type == 'file':
                        event = self.generate_file_event(is_anomaly)
                        self.write_event_to_csv('file', event)
                        status = "🚨 ANOMALY" if is_anomaly else "✓ Normal"
                        print(f"[{status}] File: {event['username']} {event['operation']} {event['file_size_mb']:.1f}MB")
                    
                    event_count += 1
                
                print(f"--- Total events: {event_count} ---\n")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print(f"\nStream stopped. Total events generated: {event_count}")

def main():
    parser = argparse.ArgumentParser(description='Security Event Data Generator')
    
    # Support both old and new argument styles
    parser.add_argument('--mode', choices=['stream', 'attack'], 
                       help='Generation mode')
    parser.add_argument('--anomaly-rate', type=float, default=0.1,
                       help='Probability of generating anomalies (0.0-1.0)')
    parser.add_argument('--interval', type=int, default=2,
                       help='Interval between events in stream mode (seconds)')
    parser.add_argument('--duration', type=int, default=None,
                       help='Duration to run in seconds (None=infinite)')
    
    # Alternative simple flags
    parser.add_argument('--attack', action='store_true',
                       help='Run attack simulation')
    parser.add_argument('--normal', action='store_true',
                       help='Generate only normal events')
    
    args = parser.parse_args()
    
    # Handle different argument combinations
    if args.attack or args.mode == 'attack':
        generator = SecurityDataGenerator(anomaly_rate=1.0)
        duration = args.duration if args.duration else 10
        generator.run_attack_simulation(duration=duration)
    
    elif args.normal:
        generator = SecurityDataGenerator(anomaly_rate=0.0)
        generator.run_stream_mode(interval_seconds=args.interval, duration=args.duration)
    
    elif args.mode == 'stream':
        generator = SecurityDataGenerator(anomaly_rate=args.anomaly_rate)
        generator.run_stream_mode(interval_seconds=args.interval, duration=args.duration)
    
    else:
        # Default: stream mode with specified anomaly rate
        generator = SecurityDataGenerator(anomaly_rate=args.anomaly_rate)
        generator.run_stream_mode(interval_seconds=args.interval, duration=args.duration)

if __name__ == "__main__":
    main()