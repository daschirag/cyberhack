#!/usr/bin/env python3
"""
Environment Setup Script for Anomaly Detection System
This script helps users set up their .env file with proper configuration.
"""

import os
import shutil
from pathlib import Path

def setup_environment():
    """Set up the .env file from the template"""
    
    print("🛡️  Anomaly Detection System - Environment Setup")
    print("=" * 50)
    
    # Check if .env already exists
    env_file = Path(".env")
    template_file = Path("env_config.txt")
    
    if env_file.exists():
        response = input("⚠️  .env file already exists. Overwrite? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Setup cancelled.")
            return
    
    # Check if template exists
    if not template_file.exists():
        print(f"❌ Template file {template_file} not found!")
        print("Please ensure env_config.txt exists in the current directory.")
        return
    
    try:
        # Copy template to .env
        shutil.copy2(template_file, env_file)
        print(f"✅ Created .env file from {template_file}")
        
        # Get user input for API key
        print("\n🔑 OpenAI API Key Configuration")
        print("You can get an API key from: https://platform.openai.com/api-keys")
        
        api_key = input("Enter your OpenAI API key (or press Enter to skip): ").strip()
        
        if api_key:
            # Update the .env file with the API key
            with open(env_file, 'r') as f:
                content = f.read()
            
            content = content.replace('your_openai_api_key_here', api_key)
            
            with open(env_file, 'w') as f:
                f.write(content)
            
            print("✅ OpenAI API key configured!")
        else:
            print("ℹ️  Skipped API key configuration. You can edit .env later.")
        
        print("\n🎉 Environment setup complete!")
        print("\nNext steps:")
        print("1. Review and edit .env file if needed")
        print("2. Run: python run_demo.py")
        print("3. Or run components separately:")
        print("   - python anomaly_detection.py")
        print("   - streamlit run dashboard.py")
        
    except Exception as e:
        print(f"❌ Error setting up environment: {e}")

if __name__ == "__main__":
    setup_environment()
