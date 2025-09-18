#!/usr/bin/env python3
"""
Simple Demo Script for Real-Time Anomaly Detection System
Demonstrates the core concepts without complex dependencies
"""

import sys
import os
import time
import random
from datetime import datetime
import json

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from anomaly_detection import PathwayAnomalyDetectionSystem
from data_generator import DataGenerator

def print_banner():
    """Print demo banner"""
    print("=" * 60)
    print("🛡️  REAL-TIME ANOMALY DETECTION SYSTEM DEMO")
    print("=" * 60)
    print("📊 Monitoring: Login patterns, Network traffic, File transfers")
    print("⚡ Demonstrating real-time streaming concepts")
    print("🎯 Perfect for hackathon demonstrations")
    print("=" * 60)

def simulate_real_time_demo():
    """Simulate a real-time demo with attack scenarios"""
    print("\n🚀 Starting Real-Time Demo...")
    
    # Initialize systems
    detection_system = PathwayAnomalyDetectionSystem()
    data_generator = DataGenerator()
    
    print("✅ Systems initialized!")
    print("📡 Generating events...")
    
    # Generate some normal events first
    print("\n📈 Phase 1: Normal Traffic (30 seconds)")
    for i in range(10):
        event_type = random.choice(["login", "network", "file_transfer"])
        
        if event_type == "login":
            event = data_generator.event_generator.generate_login_event(is_attack=False)
        elif event_type == "network":
            event = data_generator.event_generator.generate_network_event(is_attack=False)
        else:
            event = data_generator.event_generator.generate_file_transfer_event(is_attack=False)
        
        # Process event
        alerts = detection_system.process_event(event)
        
        print(f"📤 {event['type']}: {event.get('user_id', event.get('requests_per_minute', 'N/A'))}")
        
        if alerts:
            for alert in alerts:
                print(f"🚨 ALERT: {alert['detector']} - Risk: {alert['risk_score']:.2f}")
        
        time.sleep(1)
    
    # Generate attack events
    print("\n🎯 Phase 2: Attack Simulation (30 seconds)")
    attack_events = data_generator.run_attack_scenario("coordinated")
    
    for event in attack_events:
        alerts = detection_system.process_event(event)
        print(f"📤 {event['type']}: {event.get('user_id', event.get('requests_per_minute', 'N/A'))}")
        
        if alerts:
            for alert in alerts:
                print(f"🚨 ALERT: {alert['detector']} - Risk: {alert['risk_score']:.2f}")
                print(f"   💡 {alert['explanation']}")
        
        time.sleep(0.5)
    
    # Show final summary
    print("\n📊 Final Summary:")
    summary = detection_system.get_risk_summary()
    print(f"   Overall Risk: {summary['overall_risk']}")
    print(f"   Average Score: {summary['score']:.2f}")
    print(f"   Total Alerts: {summary['alert_count']}")
    
    print("\n✅ Demo completed successfully!")
    print("🎉 This demonstrates real-time anomaly detection concepts!")

def interactive_demo():
    """Interactive demo mode"""
    print("\n🎮 Interactive Demo Mode")
    print("Choose an option:")
    print("1. Run coordinated attack scenario")
    print("2. Run DDoS attack scenario") 
    print("3. Run insider threat scenario")
    print("4. Generate normal traffic")
    print("5. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == "1":
                print("\n🎯 Running Coordinated Attack Scenario...")
                run_scenario("coordinated")
            elif choice == "2":
                print("\n🌊 Running DDoS Attack Scenario...")
                run_scenario("ddos")
            elif choice == "3":
                print("\n👤 Running Insider Threat Scenario...")
                run_scenario("insider")
            elif choice == "4":
                print("\n📈 Generating Normal Traffic...")
                run_scenario("normal")
            elif choice == "5":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break

def run_scenario(scenario_name):
    """Run a specific scenario"""
    detection_system = PathwayAnomalyDetectionSystem()
    data_generator = DataGenerator()
    
    if scenario_name == "normal":
        # Generate normal events
        for i in range(5):
            event_type = random.choice(["login", "network", "file_transfer"])
            
            if event_type == "login":
                event = data_generator.event_generator.generate_login_event(is_attack=False)
            elif event_type == "network":
                event = data_generator.event_generator.generate_network_event(is_attack=False)
            else:
                event = data_generator.event_generator.generate_file_transfer_event(is_attack=False)
            
            alerts = detection_system.process_event(event)
            print(f"📤 {event['type']}: {event.get('user_id', event.get('requests_per_minute', 'N/A'))}")
            
            if alerts:
                for alert in alerts:
                    print(f"🚨 ALERT: {alert['detector']} - Risk: {alert['risk_score']:.2f}")
            
            time.sleep(1)
    else:
        # Run attack scenario
        events = data_generator.run_attack_scenario(scenario_name)
        
        for event in events:
            alerts = detection_system.process_event(event)
            print(f"📤 {event['type']}: {event.get('user_id', event.get('requests_per_minute', 'N/A'))}")
            
            if alerts:
                for alert in alerts:
                    print(f"🚨 ALERT: {alert['detector']} - Risk: {alert['risk_score']:.2f}")
                    print(f"   💡 {alert['explanation']}")
            
            time.sleep(0.5)

def main():
    """Main demo function"""
    print_banner()
    
    print("\nChoose demo mode:")
    print("1. Automated demo (recommended for presentations)")
    print("2. Interactive demo (explore different scenarios)")
    
    try:
        choice = input("\nEnter your choice (1-2): ").strip()
        
        if choice == "1":
            simulate_real_time_demo()
        elif choice == "2":
            interactive_demo()
        else:
            print("❌ Invalid choice. Running automated demo...")
            simulate_real_time_demo()
            
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted. Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure all dependencies are installed: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
