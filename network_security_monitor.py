#!/usr/bin/env python3
"""
Network Security Monitor - Intrusion Detection System
Purpose: Detect network attacks for cybersecurity learning

"""

import socket
import struct
import datetime
import time
import os
import sys
from collections import defaultdict

# Tracking dictionaries for attack detection
connection_attempts = {}
port_scan_tracker = defaultdict(set)
alert_log = []
suspicious_ips = set()
packet_counter = 0

def clear_screen():
    """Clear terminal for better display - works on Windows and Linux"""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_timestamp():
    """Return formatted current timestamp"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_alert(ip_address, alert_type, details=""):
    """Save alerts to both memory and log file"""
    timestamp = get_timestamp()
    alert_entry = f"[{timestamp}] ALERT: {alert_type} from {ip_address} | {details}"
    
    print(f"\n⚠️  {alert_entry}")
    alert_log.append(alert_entry)
    
    # Write to log file
    try:
        with open("security_alerts.log", "a") as log_file:
            log_file.write(alert_entry + "\n")
    except:
        pass

def detect_port_scan(ip_address, current_time):
    """
    Detects port scanning by tracking unique ports per IP
    If an IP connects to many different ports quickly, it's suspicious
    """
    if len(port_scan_tracker[ip_address]) >= 5:
        if ip_address not in suspicious_ips:
            suspicious_ips.add(ip_address)
            log_alert(ip_address, "Port Scan Detected", 
                     f"Connected to {len(port_scan_tracker[ip_address])} different ports")
            return True
    return False

def detect_dos_attack(ip_address):
    """
    Detects possible DoS/flood attack by counting connection frequency
    More than 20 connections in 10 seconds is suspicious
    """
    current_time = time.time()
    
    if ip_address not in connection_attempts:
        connection_attempts[ip_address] = []
    
    # Clean old entries (keep last 10 seconds only)
    connection_attempts[ip_address] = [t for t in connection_attempts[ip_address] 
                                        if current_time - t < 10]
    
    connection_attempts[ip_address].append(current_time)
    
    # Check if too many connections in short time
    if len(connection_attempts[ip_address]) >= 20:
        if ip_address not in suspicious_ips:
            suspicious_ips.add(ip_address)
            log_alert(ip_address, "Possible DoS Attack", 
                     f"{len(connection_attempts[ip_address])} connections in 10 seconds")
            return True
    return False

def analyze_packet_content(packet_data, source_ip, dest_ip, protocol, src_port, dst_port):
    """
    Analyzes packet content for attack signatures
    I learned these patterns from OWASP Top 10 and security blogs
    """
    
    # Convert packet to string for text analysis
    try:
        packet_str = packet_data.decode('utf-8', errors='ignore').lower()
    except:
        packet_str = ""
    
    # SQL injection patterns
    sql_patterns = ["' or '1'='1", "'or'1'='1", "union select", "drop table", 
                    "--", ";--", "insert into", "xp_cmdshell", "sleep("]
    for pattern in sql_patterns:
        if pattern in packet_str:
            log_alert(source_ip, "SQL Injection Attempt", f"Pattern: {pattern}")
            return True
    
    # Path traversal patterns (trying to access system files)
    traversal_patterns = ["../", "..\\", "etc/passwd", "windows\\system32", 
                          "boot.ini", "win.ini", "cmd.exe"]
    for pattern in traversal_patterns:
        if pattern in packet_str:
            log_alert(source_ip, "Path Traversal Attempt", f"Pattern: {pattern}")
            return True
    
    # Command injection patterns
    cmd_patterns = ["; ls", "| dir", "&& whoami", "`id`", "$(cat", 
                    ";cat", "|nc ", ";nc ", "& net user"]
    for pattern in cmd_patterns:
        if pattern in packet_str:
            log_alert(source_ip, "Command Injection Attempt", f"Pattern: {pattern}")
            return True
    
    # SSH brute force detection (port 22)
    if dst_port == 22 and ("ssh" in packet_str or "password" in packet_str):
        detect_bruteforce(source_ip, "SSH", packet_str)
    
    # RDP brute force (port 3389)
    if dst_port == 3389:
        detect_bruteforce(source_ip, "RDP", packet_str)
    
    # HTTP attacks (port 80, 443, 8080)
    if dst_port in [80, 443, 8080, 8000]:
        if "../" in packet_str or "passwd" in packet_str:
            log_alert(source_ip, "Web Attack Attempt", f"Target port: {dst_port}")
    
    return False

def detect_bruteforce(ip_address, service, packet_data=""):
    """Track repeated login attempts to detect brute force attacks"""
    if not hasattr(detect_bruteforce, 'counter'):
        detect_bruteforce.counter = defaultdict(int)
    if not hasattr(detect_bruteforce, 'last_alert'):
        detect_bruteforce.last_alert = defaultdict(int)
    
    key = f"{ip_address}_{service}"
    current_time = int(time.time())
    
    detect_bruteforce.counter[key] += 1
    
    # Alert after 10 attempts, but not more than once per minute
    if detect_bruteforce.counter[key] >= 10:
        if current_time - detect_bruteforce.last_alert[key] > 60:
            detect_bruteforce.last_alert[key] = current_time
            log_alert(ip_address, f"Brute Force Attack on {service}", 
                     f"{detect_bruteforce.counter[key]} attempts detected")
            return True
    return False

def parse_ip_header(packet):
    """Parse IP header to get source and destination IP addresses"""
    try:
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        
        # Extract IP addresses from bytes
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        
        # Protocol number (6=TCP, 17=UDP, 1=ICMP)
        protocol = iph[6]
        
        # IP header length in bytes
        iph_length = ihl * 4
        
        return src_ip, dst_ip, protocol, iph_length
    except:
        return None, None, None, None

def parse_tcp_header(packet, iph_length):
    """Parse TCP header to get source and destination ports"""
    try:
        tcp_header = packet[iph_length:iph_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        
        src_port = tcph[0]
        dst_port = tcph[1]
        
        return src_port, dst_port
    except:
        return None, None

def parse_udp_header(packet, iph_length):
    """Parse UDP header to get source and destination ports"""
    try:
        udp_header = packet[iph_length:iph_length+8]
        udph = struct.unpack('!HHHH', udp_header)
        
        src_port = udph[0]
        dst_port = udph[1]
        
        return src_port, dst_port
    except:
        return None, None

def run_attack_simulation():
    """
    Educational simulation showing how different attacks work
    This doesn't actually attack anything - just demonstrates patterns
    """
    print("\n" + "="*60)
    print("🧪 ATTACK SIMULATION - Educational Demo")
    print("="*60)
    print("\nThis demonstrates what different attacks look like")
    print("so you can understand what the monitor detects\n")
    
    input("Press Enter to start simulation...")
    
    print("\n[1] Simulating Port Scan...")
    for port in [21, 22, 23, 25, 80, 443, 3389, 8080]:
        print(f"   Scanning port {port}...", end="")
        time.sleep(0.1)
        print(" ⚠️ DETECTED!")
    
    print("\n[2] Simulating Brute Force Attack...")
    for attempt in range(1, 12):
        print(f"   Login attempt {attempt} from 192.168.1.100...", end="")
        time.sleep(0.1)
        if attempt >= 10:
            print(" ⚠️ BRUTE FORCE DETECTED!")
    
    print("\n[3] Simulating SQL Injection...")
    attacks = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users;--"
    ]
    for attack in attacks:
        print(f"   Payload: {attack}", end="")
        time.sleep(0.5)
        print(" → SQL INJECTION DETECTED!")
    
    print("\n[4] Simulating Path Traversal...")
    print(f"   GET /../../../etc/passwd", end="")
    time.sleep(0.5)
    print(" → PATH TRAVERSAL DETECTED!")
    
    print("\n" + "="*60)
    print("✅ SIMULATION COMPLETE")
    print("="*60)
    print("\nYour security monitor would detect all of these attacks")
    print("in real-time on a real network.\n")
    input("Press Enter to continue...")

def view_logs():
    """Display previously saved alerts from log file"""
    print("\n" + "="*60)
    print("📜 PREVIOUS ALERTS LOG")
    print("="*60)
    
    try:
        with open("security_alerts.log", "r") as log_file:
            alerts = log_file.readlines()
        
        if alerts:
            print(f"\nTotal alerts in log: {len(alerts)}")
            print("\nMost recent alerts:\n")
            for alert in alerts[-20:]:
                print(f"   {alert.strip()}")
        else:
            print("\nNo alerts found in log file")
            
    except FileNotFoundError:
        print("\nNo log file found. Run monitoring first to generate alerts.")
    except Exception as e:
        print(f"\nError reading log: {e}")
    
    input("\nPress Enter to continue...")

def start_monitoring():
    """
    Main function to start packet capture and analysis
    This was the hardest part to get working across different OS
    """
    global packet_counter
    
    print("="*60)
    print("🛡️  NETWORK SECURITY MONITOR")
    print("="*60)
    print("\n⚠️  IMPORTANT: This tool requires administrator/root privileges")
    print("⚠️  Only use on networks you own or have permission to monitor")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY - Learn how attacks work")
    print("\nPress Ctrl+C to stop monitoring and view summary")
    
    input("\nPress Enter to start monitoring...")
    clear_screen()
    
    print(f"[{get_timestamp()}] Monitoring started...")
    print("Analyzing network traffic for suspicious patterns\n")
    
    time.sleep(1)
    
    try:
        # Create raw socket (different for Windows vs Linux)
        if os.name == 'nt':  # Windows
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind(('0.0.0.0', 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode to see all traffic
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:  # Linux/Mac
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        while True:
            # Receive packet
            packet_data, addr = sniffer.recvfrom(65535)
            packet_counter += 1
            
            # Parse IP header
            src_ip, dst_ip, protocol, iph_length = parse_ip_header(packet_data)
            
            if src_ip is None:
                continue
            
            # Filter for local network traffic (makes analysis cleaner)
            # Change this to your network range if needed
            is_local = (src_ip.startswith('192.168.') or 
                       src_ip.startswith('10.') or 
                       src_ip.startswith('172.16.') or
                       src_ip == '127.0.0.1')
            
            if not is_local:
                continue  # Skip external traffic for now
            
            # Track ports for scan detection
            if protocol == 6:  # TCP
                src_port, dst_port = parse_tcp_header(packet_data, iph_length)
                if src_port and dst_port:
                    port_scan_tracker[src_ip].add(dst_port)
                    detect_port_scan(src_ip, time.time())
                    detect_dos_attack(src_ip)
                    analyze_packet_content(packet_data, src_ip, dst_ip, protocol, src_port, dst_port)
                    
                    # Show suspicious activity
                    if len(port_scan_tracker[src_ip]) > 3:
                        print(f"[{get_timestamp()}] Suspicious: {src_ip} accessed {len(port_scan_tracker[src_ip])} ports", end="\r")
            
            elif protocol == 17:  # UDP
                src_port, dst_port = parse_udp_header(packet_data, iph_length)
                if src_port and dst_port:
                    port_scan_tracker[src_ip].add(dst_port)
            
            # Status update every 500 packets
            if packet_counter % 500 == 0:
                print(f"\n[{get_timestamp()}] Active - Packets: {packet_counter}, Alerts: {len(alert_log)}")
                
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print("📊 MONITORING SUMMARY")
        print("="*60)
        print(f"Total packets captured: {packet_counter}")
        print(f"Total alerts generated: {len(alert_log)}")
        print(f"Suspicious IPs detected: {len(suspicious_ips)}")
        
        if suspicious_ips:
            print("\n🚨 Suspicious IP Addresses Found:")
            for ip in suspicious_ips:
                print(f"   → {ip}")
        
        if alert_log:
            print(f"\n📋 Last 5 Alerts:")
            for alert in alert_log[-5:]:
                print(f"   {alert}")
        
        print(f"\n✅ Full log saved to: security_alerts.log")
        print("\n👋 Monitoring stopped. Stay secure!")
        input("\nPress Enter to continue...")
        
    except PermissionError:
        print("\n❌ ERROR: Permission Denied!")
        print("\nThis tool needs administrator privileges to capture network packets.")
        print("\nHow to fix:")
        print("   Windows: Right-click Command Prompt → 'Run as Administrator'")
        print("   Linux/Mac: sudo python3 network_security_monitor.py")
        input("\nPress Enter to continue...")
        
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")
        print("\nTry running with administrator privileges")
        input("\nPress Enter to continue...")
        
    finally:
        # Clean up - turn off promiscuous mode on Windows
        try:
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
        except:
            pass

def main():
    """Main menu for the security monitor"""
    while True:
        clear_screen()
        print("\n" + "="*50)
        print("🔒 NETWORK SECURITY TOOLKIT")
        print("="*50)
        print("1. 🛡️  Start Real-time Monitoring")
        print("2. 📋 View Previous Alerts")
        print("3. 🧪 Run Attack Simulation (Learn how attacks work)")
        print("4. ❌ Exit")
        print("="*50)
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == "1":
            start_monitoring()
            
        elif choice == "2":
            view_logs()
            
        elif choice == "3":
            clear_screen()
            run_attack_simulation()
            
        elif choice == "4":
            print("\n👋 Stay secure! Goodbye!")
            sys.exit(0)
            
        else:
            print("\n❌ Invalid option. Please choose 1-4")
            time.sleep(1)

if __name__ == "__main__":
    # Check Python version
    if sys.version_info[0] < 3:
        print("This program requires Python 3.x")
        sys.exit(1)
    
    main()