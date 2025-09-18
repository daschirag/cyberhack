"""
Realistic Event Simulator with Attack Scenarios
Generates cybersecurity events for testing the anomaly detection system
"""

import json
import random
import time
import argparse
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventGenerator:
    """Base class for generating realistic cybersecurity events"""
    
    def __init__(self):
        self.users = [
            "john.doe", "jane.smith", "bob.wilson", "alice.brown", 
            "charlie.davis", "diana.miller", "eve.jones", "frank.garcia"
        ]
        self.countries = [
            "USA", "Canada", "UK", "Germany", "France", "Japan", 
            "Australia", "India", "Brazil", "Mexico"
        ]
        self.suspicious_countries = ["Russia", "China", "North Korea", "Iran"]
        self.file_types = [".pdf", ".docx", ".xlsx", ".zip", ".rar", ".7z", ".sql", ".db", ".csv", ".txt"]
        
    def generate_login_event(self, is_attack: bool = False) -> Dict[str, Any]:
        """Generate a login event"""
        user_id = random.choice(self.users)
        
        if is_attack:
            # Attack scenario: suspicious login
            country = random.choice(self.suspicious_countries)
            hour = random.choice([1, 2, 3, 4, 5, 23])  # Odd hours
        else:
            # Normal scenario
            country = random.choice(self.countries)
            hour = random.randint(6, 22)  # Normal hours
            
        return {
            "type": "login",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "country": country,
            "hour": hour,
            "ip_address": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]),
            "success": random.choice([True, True, True, False])  # 75% success rate
        }
    
    def generate_network_event(self, is_attack: bool = False) -> Dict[str, Any]:
        """Generate a network traffic event"""
        if is_attack:
            # Attack scenario: DDoS-like traffic spike
            requests_per_minute = random.randint(50000, 100000)
            endpoint = random.choice(["/api/login", "/api/data", "/api/files"])
        else:
            # Normal scenario
            requests_per_minute = random.randint(100, 2000)
            endpoint = random.choice(["/api/status", "/api/health", "/api/metrics"])
            
        return {
            "type": "network",
            "timestamp": datetime.now().isoformat(),
            "requests_per_minute": requests_per_minute,
            "endpoint": endpoint,
            "response_time_ms": random.randint(50, 500),
            "status_codes": {
                "200": random.randint(80, 95),
                "404": random.randint(1, 10),
                "500": random.randint(0, 5)
            },
            "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
    
    def generate_file_transfer_event(self, is_attack: bool = False) -> Dict[str, Any]:
        """Generate a file transfer event"""
        user_id = random.choice(self.users)
        
        if is_attack:
            # Attack scenario: large file download (data exfiltration)
            file_size_mb = random.randint(500, 2000)
            file_type = random.choice([".zip", ".rar", ".7z", ".sql", ".db"])
            action = "download"
        else:
            # Normal scenario
            file_size_mb = random.randint(1, 50)
            file_type = random.choice([".pdf", ".docx", ".xlsx", ".txt"])
            action = random.choice(["upload", "download"])
            
        return {
            "type": "file_transfer",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "file_name": f"document_{random.randint(1000, 9999)}{file_type}",
            "file_size_mb": file_size_mb,
            "file_type": file_type,
            "action": action,
            "destination": random.choice(["local", "cloud", "external"])
        }

class AttackScenario:
    """Predefined attack scenarios for demonstration"""
    
    def __init__(self, event_generator: EventGenerator):
        self.generator = event_generator
        
    def coordinated_attack(self) -> List[Dict[str, Any]]:
        """Simulate a coordinated multi-vector attack"""
        events = []
        
        # Phase 1: Reconnaissance - normal-looking network traffic
        for _ in range(5):
            events.append(self.generator.generate_network_event(is_attack=False))
            time.sleep(0.1)
            
        # Phase 2: Initial breach - suspicious login
        events.append(self.generator.generate_login_event(is_attack=True))
        time.sleep(0.2)
        
        # Phase 3: Data exfiltration - large file transfers
        for _ in range(3):
            events.append(self.generator.generate_file_transfer_event(is_attack=True))
            time.sleep(0.3)
            
        # Phase 4: Cover tracks - more suspicious logins
        for _ in range(2):
            events.append(self.generator.generate_login_event(is_attack=True))
            time.sleep(0.1)
            
        return events
    
    def ddos_attack(self) -> List[Dict[str, Any]]:
        """Simulate a DDoS attack"""
        events = []
        
        # Rapid burst of network traffic
        for _ in range(20):
            events.append(self.generator.generate_network_event(is_attack=True))
            time.sleep(0.05)
            
        return events
    
    def insider_threat(self) -> List[Dict[str, Any]]:
        """Simulate an insider threat scenario"""
        events = []
        
        # Normal login from familiar location
        events.append(self.generator.generate_login_event(is_attack=False))
        time.sleep(0.5)
        
        # Suspicious file transfers
        for _ in range(5):
            events.append(self.generator.generate_file_transfer_event(is_attack=True))
            time.sleep(0.2)
            
        return events

class DataGenerator:
    """Main data generator for the anomaly detection system"""
    
    def __init__(self):
        self.event_generator = EventGenerator()
        self.attack_scenario = AttackScenario(self.event_generator)
        
    def generate_normal_traffic(self, duration_minutes: int = 1) -> List[Dict[str, Any]]:
        """Generate normal traffic for baseline"""
        events = []
        end_time = time.time() + (duration_minutes * 60)
        
        while time.time() < end_time:
            # Randomly choose event type
            event_type = random.choice(["login", "network", "file_transfer"])
            
            if event_type == "login":
                events.append(self.event_generator.generate_login_event(is_attack=False))
            elif event_type == "network":
                events.append(self.event_generator.generate_network_event(is_attack=False))
            else:
                events.append(self.event_generator.generate_file_transfer_event(is_attack=False))
                
            time.sleep(random.uniform(0.5, 2.0))  # Random interval
            
        return events
    
    def run_attack_scenario(self, scenario_name: str) -> List[Dict[str, Any]]:
        """Run a specific attack scenario"""
        print(f"🎯 Running attack scenario: {scenario_name}")
        
        if scenario_name == "coordinated":
            return self.attack_scenario.coordinated_attack()
        elif scenario_name == "ddos":
            return self.attack_scenario.ddos_attack()
        elif scenario_name == "insider":
            return self.attack_scenario.insider_threat()
        else:
            print(f"❌ Unknown scenario: {scenario_name}")
            return []
    
    def stream_events(self, mode: str = "normal", duration_minutes: int = 5):
        """Stream events continuously"""
        print(f"📡 Starting event stream in {mode} mode for {duration_minutes} minutes...")
        
        end_time = time.time() + (duration_minutes * 60)
        event_count = 0
        
        try:
            while time.time() < end_time:
                if mode == "attack":
                    # Occasionally inject attack events
                    if random.random() < 0.1:  # 10% chance of attack
                        scenario = random.choice(["coordinated", "ddos", "insider"])
                        attack_events = self.run_attack_scenario(scenario)
                        for event in attack_events:
                            print(f"📤 {event['type']}: {json.dumps(event, indent=2)}")
                            event_count += 1
                            time.sleep(0.1)
                    else:
                        # Normal event
                        event_type = random.choice(["login", "network", "file_transfer"])
                        if event_type == "login":
                            event = self.event_generator.generate_login_event(is_attack=False)
                        elif event_type == "network":
                            event = self.event_generator.generate_network_event(is_attack=False)
                        else:
                            event = self.event_generator.generate_file_transfer_event(is_attack=False)
                            
                        print(f"📤 {event['type']}: {json.dumps(event, indent=2)}")
                        event_count += 1
                else:
                    # Normal mode
                    event_type = random.choice(["login", "network", "file_transfer"])
                    if event_type == "login":
                        event = self.event_generator.generate_login_event(is_attack=False)
                    elif event_type == "network":
                        event = self.event_generator.generate_network_event(is_attack=False)
                    else:
                        event = self.event_generator.generate_file_transfer_event(is_attack=False)
                        
                    print(f"📤 {event['type']}: {json.dumps(event, indent=2)}")
                    event_count += 1
                
                time.sleep(random.uniform(1.0, 3.0))  # Random interval
                
        except KeyboardInterrupt:
            print(f"\n🛑 Event streaming stopped. Generated {event_count} events.")
            
        print(f"✅ Event streaming completed. Total events: {event_count}")

def main():
    """Main function for the data generator"""
    parser = argparse.ArgumentParser(description="Generate cybersecurity events for anomaly detection")
    parser.add_argument("--mode", choices=["normal", "attack"], default="normal",
                       help="Mode: normal traffic or attack simulation")
    parser.add_argument("--duration", type=int, default=5,
                       help="Duration in minutes (default: 5)")
    parser.add_argument("--scenario", choices=["coordinated", "ddos", "insider"],
                       help="Specific attack scenario to run")
    
    args = parser.parse_args()
    
    generator = DataGenerator()
    
    if args.scenario:
        # Run specific attack scenario
        events = generator.run_attack_scenario(args.scenario)
        for event in events:
            print(f"📤 {event['type']}: {json.dumps(event, indent=2)}")
            time.sleep(0.5)
    else:
        # Stream events continuously
        generator.stream_events(mode=args.mode, duration_minutes=args.duration)

if __name__ == "__main__":
    main()
