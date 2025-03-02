"""
Test script for the log parser module.
This script reads sample log files and tests the parsing functionality.
"""

import os
import sys
import json
from utils import LogParser

def main():
    """Main function to test log parsing"""
    # Initialize log parser
    parser = LogParser()
    
    # Add default templates (similar to what's in ThreatAnalyzer._load_log_templates)
    # Fortinet firewall log template
    parser.add_template(
        source_type="fortinet",
        regex_pattern=r'date=(?P<date>[^ ]+) time=(?P<time>[^ ]+) .*?level=(?P<level>[^ ]+) .*?srcip=(?P<srcip>[^ ]+) srcport=(?P<srcport>[^ ]+) dstip=(?P<dstip>[^ ]+) dstport=(?P<dstport>[^ ]+) .*?action=(?P<action>[^ ]+)',
        field_mapping={
            "date": "date",
            "time": "time",
            "level": "level",
            "source_ip": "srcip",
            "source_port": "srcport",
            "destination_ip": "dstip",
            "destination_port": "dstport",
            "action": "action"
        },
        description="Fortinet FortiGate firewall logs"
    )
    
    # Linux syslog SSH template
    parser.add_template(
        source_type="linux_syslog",
        regex_pattern=r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>[^ ]+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)',
        field_mapping={
            "date": "date",
            "hostname": "hostname",
            "pid": "pid",
            "message": "message"
        },
        description="Linux syslog SSH login attempts"
    )
    
    # Azure WAF log template
    parser.add_template(
        source_type="azure_waf",
        regex_pattern=r'.*clientIP=(?P<clientip>[^ ]+).*resourceId=(?P<resourceid>[^ ]+).*requestUri="(?P<uri>[^"]+)".*ruleId=(?P<ruleid>[^ ]+).*action=(?P<action>[^ ]+)',
        field_mapping={
            "client_ip": "clientip",
            "resource_id": "resourceid",
            "request_uri": "uri",
            "rule_id": "ruleid",
            "action": "action"
        },
        description="Azure WAF logs"
    )
    
    # Get the samples directory
    samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
    
    # Test Fortinet logs
    print("\n=== Testing Fortinet logs ===")
    fortinet_log_file = os.path.join(samples_dir, "fortinet_logs.txt")
    test_log_file(parser, fortinet_log_file, "fortinet")
    
    # Test Linux syslog
    print("\n=== Testing Linux syslog ===")
    linux_log_file = os.path.join(samples_dir, "linux_syslog.txt")
    test_log_file(parser, linux_log_file, "linux_syslog")
    
    # Test Azure WAF logs
    print("\n=== Testing Azure WAF logs ===")
    azure_log_file = os.path.join(samples_dir, "azure_waf_logs.txt")
    test_log_file(parser, azure_log_file, "azure_waf")

def test_log_file(parser, log_file, source_type):
    """Test parsing a log file"""
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        success_count = 0
        total_count = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            total_count += 1
            parsed = parser.parse_log(line, source_type)
            
            if parsed:
                success_count += 1
                severity = parser.extract_severity(parsed)
                print(f"Parsed successfully. Severity: {severity:.2f}")
                print(f"Sample fields: {json.dumps({k: v for k, v in parsed.items() if k != 'raw_log'})[:200]}...")
            else:
                print(f"Failed to parse: {line[:100]}...")
        
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        print(f"\nResults for {source_type}:")
        print(f"Total logs: {total_count}")
        print(f"Successfully parsed: {success_count}")
        print(f"Success rate: {success_rate:.2f}%")
        
    except Exception as e:
        print(f"Error testing {log_file}: {e}")

if __name__ == "__main__":
    main() 