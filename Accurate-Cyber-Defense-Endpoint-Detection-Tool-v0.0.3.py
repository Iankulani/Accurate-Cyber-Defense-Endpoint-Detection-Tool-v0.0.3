"""
ACCURATE CYBER DRILL TOOL - ENHANCED EDITION WITH DATA VISUALIZATION
Author: Ian Carter Kulani
Version: 3.0.0
Integrated Features: Network Monitoring, Intrusion Detection, Traffic Generation, 
                     Threat Analysis, Telegram Integration, Advanced Scanning
                     Data Visualization (Charts & Graphs), Real-time Analytics
"""

import sys
import os
import time
import json
import logging
import configparser
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading
import queue
import argparse

import signal
import hashlib
import base64
import zipfile
import tempfile

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import sqlite3
import ipaddress
import re
import shutil

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# Data Visualization imports
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure
    from matplotlib.patches import Rectangle
    import seaborn as sns
    import pandas as pd
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Install matplotlib, seaborn, pandas for data visualization: pip install matplotlib seaborn pandas")

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Constants
VERSION = "3.0.0"
AUTHOR = "Cyber Security War Tool Team"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "network_threats.db"
REPORT_DIR = "reports"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0"
    }
}

class DataVisualizer:
    """Advanced data visualization for network and threat data"""
    
    def __init__(self):
        if not MATPLOTLIB_AVAILABLE:
            self.available = False
            return
        self.available = True
        plt.style.use('dark_background')
        sns.set_palette("husl")
        
    def create_port_scan_chart(self, scan_data: Dict[str, Any], parent_frame):
        """Create visualization for port scan results"""
        if not self.available:
            return None
            
        fig = Figure(figsize=(10, 6), dpi=100)
        ax = fig.add_subplot(111)
        
        open_ports = scan_data.get('open_ports', [])
        if isinstance(open_ports[0], dict):
            ports = [p['port'] for p in open_ports]
            services = [p.get('service', 'Unknown') for p in open_ports]
        else:
            ports = open_ports
            services = ['Port ' + str(p) for p in ports]
        
        # Create bar chart
        y_pos = np.arange(len(ports))
        colors = plt.cm.viridis(np.linspace(0, 1, len(ports)))
        
        ax.barh(y_pos, [1]*len(ports), color=colors, edgecolor='white')
        ax.set_yticks(y_pos)
        ax.set_yticklabels([f"Port {p}" for p in ports])
        ax.set_xlabel('Status')
        ax.set_title(f'Open Ports Scan - {scan_data.get("target", "Unknown")}')
        
        # Add service labels
        for i, (port, service) in enumerate(zip(ports, services)):
            ax.text(0.5, i, f"{service}", va='center', ha='center', color='white', fontweight='bold')
        
        fig.tight_layout()
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        return canvas
    
    def create_threat_distribution_chart(self, threat_data: List[Dict], parent_frame):
        """Create pie chart for threat distribution"""
        if not self.available:
            return None
            
        fig = Figure(figsize=(8, 8), dpi=100)
        ax = fig.add_subplot(111)
        
        # Count threats by type
        threat_counts = {}
        for threat in threat_data:
            ttype = threat.get('threat_type', 'Unknown')
            threat_counts[ttype] = threat_counts.get(ttype, 0) + 1
        
        if not threat_counts:
            ax.text(0.5, 0.5, 'No threat data available', 
                   ha='center', va='center', fontsize=12)
            ax.set_title('Threat Distribution')
        else:
            labels = list(threat_counts.keys())
            sizes = list(threat_counts.values())
            colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors,
                                             autopct='%1.1f%%', startangle=90)
            
            # Style the text
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            ax.set_title('Threat Type Distribution', fontsize=14, fontweight='bold')
        
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        return canvas
    
    def create_traffic_flow_chart(self, traffic_data: List[Dict], parent_frame):
        """Create network traffic flow visualization"""
        if not self.available:
            return None
            
        fig = Figure(figsize=(12, 6), dpi=100)
        ax = fig.add_subplot(111)
        
        protocols = ['TCP', 'UDP', 'ICMP', 'Other']
        counts = [0, 0, 0, 0]
        
        for data in traffic_data:
            proto = data.get('protocol', '').upper()
            if 'TCP' in proto:
                counts[0] += data.get('packet_count', 0)
            elif 'UDP' in proto:
                counts[1] += data.get('packet_count', 0)
            elif 'ICMP' in proto:
                counts[2] += data.get('packet_count', 0)
            else:
                counts[3] += data.get('packet_count', 0)
        
        x_pos = np.arange(len(protocols))
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
        
        bars = ax.bar(x_pos, counts, color=colors, edgecolor='white', linewidth=2)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(protocols, rotation=45, ha='right')
        ax.set_ylabel('Packet Count', fontweight='bold')
        ax.set_title('Network Traffic by Protocol', fontsize=14, fontweight='bold')
        
        # Add value labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                   f'{count:,}', ha='center', va='bottom', fontweight='bold')
        
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        return canvas
    
    def create_timeline_chart(self, timeline_data: List[Dict], parent_frame):
        """Create timeline visualization for events"""
        if not self.available:
            return None
            
        fig = Figure(figsize=(12, 6), dpi=100)
        ax = fig.add_subplot(111)
        
        # Parse timeline data
        times = []
        events = []
        severities = []
        
        for event in timeline_data:
            if 'timestamp' in event:
                try:
                    dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    times.append(dt)
                    events.append(event.get('event_type', 'Unknown'))
                    
                    # Color code by severity
                    severity = event.get('severity', 'medium').lower()
                    if severity == 'high':
                        severities.append('#FF5252')
                    elif severity == 'medium':
                        severities.append('#FFD740')
                    else:
                        severities.append('#69F0AE')
                except:
                    continue
        
        if times:
            # Create scatter plot for events
            y_pos = np.random.rand(len(times)) * 0.8 + 0.1  # Random y positions
            
            scatter = ax.scatter(times, y_pos, s=100, c=severities, alpha=0.7, edgecolors='white')
            
            # Add event labels
            for i, (time, event, y) in enumerate(zip(times, events, y_pos)):
                ax.annotate(event, (time, y), textcoords="offset points", 
                          xytext=(0,10), ha='center', fontsize=8)
            
            ax.set_xlabel('Time', fontweight='bold')
            ax.set_yticks([])
            ax.set_title('Security Events Timeline', fontsize=14, fontweight='bold')
            
            # Format x-axis
            fig.autofmt_xdate()
        
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        return canvas

class EnhancedDatabaseManager:
    """Enhanced database manager with visualization data support"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.visualizer = DataVisualizer()
        self.init_database()
    
    def init_database(self):
        """Initialize database with visualization tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Existing tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_duration REAL
            )
        ''')
        
        # New tables for visualization data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visualization_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chart_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                title TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_scan_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                port INTEGER NOT NULL,
                service TEXT,
                state TEXT,
                version TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_results(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS real_time_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_visualization_data(self, chart_type: str, data: Dict, title: str = ""):
        """Save visualization data to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO visualization_data (chart_type, data_json, title) VALUES (?, ?, ?)',
            (chart_type, json.dumps(data), title)
        )
        conn.commit()
        conn.close()
    
    def get_port_scan_for_visualization(self, limit: int = 10) -> List[Dict]:
        """Get port scan data for visualization"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sr.ip_address, sr.scan_type, sr.open_ports, sr.services, sr.timestamp
            FROM scan_results sr
            ORDER BY sr.timestamp DESC LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            ip, scan_type, open_ports_json, services_json, timestamp = row
            
            try:
                open_ports = json.loads(open_ports_json) if open_ports_json else []
                services = json.loads(services_json) if services_json else []
                
                # Create structured data for visualization
                ports_data = []
                if isinstance(open_ports, list) and isinstance(services, list):
                    for i, port in enumerate(open_ports[:20]):  # Limit to 20 ports for display
                        service = services[i] if i < len(services) else "Unknown"
                        ports_data.append({
                            'port': port,
                            'service': service,
                            'target': ip
                        })
                
                results.append({
                    'target': ip,
                    'scan_type': scan_type,
                    'open_ports': ports_data,
                    'timestamp': timestamp,
                    'total_ports': len(open_ports)
                })
            except:
                continue
        
        conn.close()
        return results
    
    def get_threat_data_for_visualization(self, hours: int = 24) -> List[Dict]:
        """Get threat data for visualization"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_type, severity, COUNT(*) as count
            FROM threat_logs
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type, severity
            ORDER BY count DESC
        ''', (f'-{hours} hours',))
        
        results = []
        for threat_type, severity, count in cursor.fetchall():
            results.append({
                'threat_type': threat_type,
                'severity': severity,
                'count': count
            })
        
        conn.close()
        return results

class EnhancedNetworkScanner:
    """Enhanced network scanner with visualization support"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def comprehensive_scan_with_viz(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive scan and prepare visualization data"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'visualizations': []
        }
        
        try:
            # Ping first
            ping_result = self.ping_ip(target)
            results['ping'] = ping_result
            
            # Port scan
            port_result = self.port_scan(target, "1-1000")
            results['port_scan'] = port_result
            
            if port_result['success']:
                # Save for visualization
                viz_data = {
                    'target': target,
                    'open_ports': port_result.get('open_ports', []),
                    'scan_type': 'comprehensive',
                    'timestamp': results['timestamp']
                }
                self.db_manager.save_visualization_data('port_scan', viz_data, f'Port Scan - {target}')
                
                # Create visualization data structure
                results['visualizations'].append({
                    'type': 'port_scan',
                    'data': viz_data,
                    'title': f'Port Scan Results for {target}'
                })
            
            # Get location info
            location = self.get_ip_location(target)
            results['location'] = location
            
            # Threat assessment
            threats = self.db_manager.get_threat_data_for_visualization(24)
            ip_threats = [t for t in threats if t.get('ip_address') == target]
            
            if ip_threats:
                results['threats'] = ip_threats
                results['visualizations'].append({
                    'type': 'threat_distribution',
                    'data': ip_threats,
                    'title': f'Threat History for {target}'
                })
            
            results['success'] = True
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def ping_ip(self, ip: str) -> str:
        """Enhanced ping with visualization data"""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                response = f"✅ {ip} is reachable\n\n"
                
                # Extract ping times for visualization
                times = []
                lines = result.stdout.split('\n')
                for line in lines:
                    if "time=" in line or "time<" in line:
                        match = re.search(r'time[=<>](\d+(?:\.\d+)?)', line)
                        if match:
                            times.append(float(match.group(1)))
                        response += f"  Response: {line.strip()}\n"
                
                # Save response times for visualization
                if times:
                    viz_data = {
                        'target': ip,
                        'response_times': times,
                        'average': sum(times)/len(times) if times else 0,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.db_manager.save_visualization_data('ping_times', viz_data, f'Ping Times - {ip}')
                
                return response
            else:
                return f"❌ {ip} is not reachable"
                
        except subprocess.TimeoutExpired:
            return f"❌ Ping timeout for {ip}"
        except Exception as e:
            return f"❌ Ping error: {str(e)}"
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Enhanced port scan with detailed results"""
        if not self.nm:
            return self.basic_port_scan(ip, ports)
        
        try:
            start_time = time.time()
            self.nm.scan(ip, ports, arguments='-T4 -sV')
            scan_duration = time.time() - start_time
            
            open_ports = []
            service_details = []
            
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    for port, port_info in self.nm[ip][proto].items():
                        if port_info['state'] == 'open':
                            open_ports.append(port)
                            service_details.append({
                                'port': port,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'state': port_info.get('state', '')
                            })
            
            # Save to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO scan_results (ip_address, scan_type, open_ports, services, scan_duration) VALUES (?, ?, ?, ?, ?)',
                (ip, 'nmap', json.dumps(open_ports), json.dumps(service_details), scan_duration)
            )
            scan_id = cursor.lastrowid
            
            # Save port details
            for detail in service_details:
                cursor.execute(
                    'INSERT INTO port_scan_details (scan_id, port, service, state, version) VALUES (?, ?, ?, ?, ?)',
                    (scan_id, detail['port'], detail['service'], detail['state'], detail['version'])
                )
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'target': ip,
                'open_ports': service_details,
                'total_open': len(open_ports),
                'scan_duration': scan_duration,
                'scan_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def basic_port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Basic port scan when nmap is not available"""
        try:
            # Parse port range
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(p.strip()) for p in ports.split(',')]
            
            open_ports = []
            service_details = []
            
            def check_port(port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port, result == 0
            
            # Use threading for faster scanning
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(check_port, port) for port in port_list[:1000]]  # Limit to 1000 ports
                
                for future in concurrent.futures.as_completed(futures):
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        service_details.append({
                            'port': port,
                            'service': self.get_service_name(port),
                            'product': '',
                            'version': '',
                            'state': 'open'
                        })
            
            return {
                'success': True,
                'target': ip,
                'open_ports': service_details,
                'total_open': len(open_ports),
                'scan_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP Proxy"
        }
        return service_map.get(port, f"Port {port}")
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location information"""
        try:
            # Try multiple services
            services = [
                f"http://ip-api.com/json/{ip}",
                f"https://ipinfo.io/{ip}/json",
                f"http://ipapi.co/{ip}/json/"
            ]
            
            location_data = {}
            for service_url in services:
                try:
                    response = requests.get(service_url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'error' not in data:
                            if 'country' in data:
                                location_data = {
                                    'country': data.get('country', 'Unknown'),
                                    'region': data.get('region', data.get('regionName', 'Unknown')),
                                    'city': data.get('city', 'Unknown'),
                                    'isp': data.get('isp', data.get('org', 'Unknown')),
                                    'coordinates': f"{data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}"
                                }
                                break
                except:
                    continue
            
            if location_data:
                return json.dumps(location_data, indent=2)
            else:
                return "Location information unavailable"
                
        except Exception as e:
            return f"Location error: {str(e)}"

class CyberDefenseGUI:
    """Enhanced GUI with data visualization capabilities"""
    
    def __init__(self, root, db_manager: EnhancedDatabaseManager, 
                 network_scanner: EnhancedNetworkScanner):
        self.root = root
        self.db_manager = db_manager
        self.scanner = network_scanner
        self.visualizer = db_manager.visualizer
        self.current_theme = "dark"
        
        self.setup_gui()
        self.update_interval = 3000  # ms
        self.update_dashboard()
    
    def setup_gui(self):
        """Setup the enhanced GUI with visualization tabs"""
        self.root.title(f"Accurate Cyber Defense v{VERSION} - Advanced Visualization")
        self.root.geometry("1400x900")
        
        # Create menu
        self.create_menu()
        
        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create enhanced tabs
        self.create_dashboard_tab()
        self.create_network_scanner_tab()
        self.create_visualization_tab()
        self.create_threat_analysis_tab()
        self.create_real_time_monitor_tab()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Save Visualization", command=self.save_visualization)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        view_menu.add_separator()
        view_menu.add_command(label="Dashboard", command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Network Scanner", command=lambda: self.notebook.select(1))
        view_menu.add_command(label="Visualization", command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Threat Analysis", command=lambda: self.notebook.select(3))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Visualization menu
        viz_menu = tk.Menu(menubar, tearoff=0)
        viz_menu.add_command(label="Port Scan Chart", command=self.show_port_scan_chart)
        viz_menu.add_command(label="Threat Distribution", command=self.show_threat_distribution)
        viz_menu.add_command(label="Traffic Analysis", command=self.show_traffic_analysis)
        viz_menu.add_command(label="Timeline View", command=self.show_timeline_view)
        menubar.add_cascade(label="Visualization", menu=viz_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Welcome panel
        welcome_frame = ttk.LabelFrame(tab, text="Welcome", padding=10)
        welcome_frame.pack(fill=tk.X, padx=10, pady=5)
        
        welcome_text = f"""🚀 ACCURATE CYBER DEFENSE v{VERSION}
        
Advanced Network Security Tool with Real-time Visualization
• Network Scanning & Monitoring
• Threat Detection & Analysis  
• Data Visualization (Charts & Graphs)
• Real-time Analytics & Reporting
        
Select a tab to begin analysis."""
        
        welcome_label = ttk.Label(welcome_frame, text=welcome_text, justify=tk.LEFT)
        welcome_label.pack(padx=5, pady=5)
        
        # Quick actions
        action_frame = ttk.LabelFrame(tab, text="Quick Actions", padding=10)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        
        action_buttons = [
            ("Quick Scan", self.quick_scan),
            ("View Threats", self.show_threats),
            ("Generate Report", self.generate_report),
            ("Open Terminal", self.open_terminal)
        ]
        
        for text, command in action_buttons:
            btn = ttk.Button(action_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    def create_network_scanner_tab(self):
        """Create enhanced network scanner tab with visualization preview"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Network Scanner")
        
        # Split into left (controls) and right (visualization) panes
        paned_window = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left pane - Controls
        control_frame = ttk.Frame(paned_window)
        paned_window.add(control_frame, weight=1)
        
        # Target configuration
        config_frame = ttk.LabelFrame(control_frame, text="Scan Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(config_frame, width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_entry = ttk.Entry(config_frame, width=15)
        self.port_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.port_entry.insert(0, "1-1000")
        
        # Scan types
        scan_frame = ttk.LabelFrame(control_frame, text="Scan Types", padding=10)
        scan_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.scan_type = tk.StringVar(value="quick")
        scan_types = [
            ("Quick Scan (Common Ports)", "quick"),
            ("Full Port Scan", "full"),
            ("Service Detection", "service"),
            ("OS Detection", "os")
        ]
        
        for i, (text, value) in enumerate(scan_types):
            rb = ttk.Radiobutton(scan_frame, text=text, variable=self.scan_type, value=value)
            rb.grid(row=i//2, column=i%2, sticky=tk.W, padx=5, pady=2)
        
        # Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        scan_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        viz_btn = ttk.Button(button_frame, text="Show Visualization", command=self.show_scan_visualization)
        viz_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(control_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=15)
        self.scan_results.pack(fill=tk.BOTH, expand=True)
        
        # Right pane - Visualization preview
        viz_frame = ttk.Frame(paned_window)
        paned_window.add(viz_frame, weight=2)
        
        self.viz_canvas_frame = ttk.Frame(viz_frame)
        self.viz_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Default visualization placeholder
        placeholder = ttk.Label(self.viz_canvas_frame, text="Visualization will appear here\nafter scan completion", 
                               justify=tk.CENTER)
        placeholder.pack(expand=True)
    
    def create_visualization_tab(self):
        """Create dedicated visualization tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Data Visualization")
        
        # Visualization selection
        selection_frame = ttk.LabelFrame(tab, text="Select Visualization", padding=10)
        selection_frame.pack(fill=tk.X, padx=10, pady=5)
        
        viz_types = [
            ("Port Scan Chart", self.show_port_scan_chart),
            ("Threat Distribution", self.show_threat_distribution),
            ("Traffic Flow", self.show_traffic_flow),
            ("Timeline View", self.show_timeline)
        ]
        
        for i, (text, command) in enumerate(viz_types):
            btn = ttk.Button(selection_frame, text=text, command=command, width=20)
            btn.grid(row=i//2, column=i%2, padx=5, pady=5)
        
        # Main visualization area
        self.viz_main_frame = ttk.Frame(tab)
        self.viz_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Control panel for visualization
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Data", command=self.refresh_visualizations).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save Chart", command=self.save_chart).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Data", command=self.export_viz_data).pack(side=tk.LEFT, padx=5)
    
    def create_threat_analysis_tab(self):
        """Create threat analysis tab with visualizations"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Threat Analysis")
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(tab, text="Threat Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create grid for stats
        self.threat_stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X, padx=5, pady=5)
        
        stats = [
            ("Total Threats (24h):", "total"),
            ("High Severity:", "high"),
            ("Medium Severity:", "medium"),
            ("Low Severity:", "low"),
            ("Recent Threats:", "recent"),
            ("Top Threat Type:", "top_type")
        ]
        
        for i, (label, key) in enumerate(stats):
            frame = ttk.Frame(stats_grid)
            frame.grid(row=i//3, column=i%3, sticky=tk.W, padx=20, pady=10)
            
            ttk.Label(frame, text=label, font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
            self.threat_stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10))
            self.threat_stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Threat visualization area
        viz_frame = ttk.LabelFrame(tab, text="Threat Visualizations", padding=10)
        viz_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create two columns for visualizations
        columns_frame = ttk.Frame(viz_frame)
        columns_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - pie chart
        self.threat_pie_frame = ttk.Frame(columns_frame)
        self.threat_pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right column - bar chart
        self.threat_bar_frame = ttk.Frame(columns_frame)
        self.threat_bar_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Threat list
        list_frame = ttk.LabelFrame(tab, text="Recent Threats", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats
        columns = ('Time', 'IP Address', 'Threat Type', 'Severity', 'Description')
        self.threats_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_real_time_monitor_tab(self):
        """Create real-time monitoring tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Real-time Monitor")
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(tab, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Monitor Interface:").pack(side=tk.LEFT, padx=5)
        self.monitor_iface = ttk.Entry(control_frame, width=15)
        self.monitor_iface.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        
        # Real-time metrics
        metrics_frame = ttk.LabelFrame(tab, text="Real-time Metrics", padding=10)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create metrics display
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, wrap=tk.WORD, height=10)
        self.metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Network traffic visualization
        traffic_frame = ttk.LabelFrame(tab, text="Network Traffic", padding=10)
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.traffic_viz_frame = ttk.Frame(traffic_frame)
        self.traffic_viz_frame.pack(fill=tk.BOTH, expand=True)
    
    def apply_theme(self):
        """Apply current theme to GUI"""
        theme = THEMES[self.current_theme]
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
    
    def switch_theme(self):
        """Switch between dark and light themes"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
    
    def start_scan(self):
        """Start network scan"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        port_range = self.port_entry.get().strip()
        scan_type = self.scan_type.get()
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Starting {scan_type} scan on {target}...\n")
        
        def perform_scan():
            try:
                # Perform comprehensive scan
                scan_result = self.scanner.comprehensive_scan_with_viz(target)
                
                # Display results
                self.scan_results.insert(tk.END, f"\nScan Results for {target}:\n")
                self.scan_results.insert(tk.END, "="*50 + "\n")
                
                if scan_result['success']:
                    # Display port scan results
                    if 'port_scan' in scan_result:
                        port_data = scan_result['port_scan']
                        if port_data['success']:
                            self.scan_results.insert(tk.END, f"Open Ports: {port_data.get('total_open', 0)}\n")
                            for port_info in port_data.get('open_ports', [])[:10]:  # Show first 10
                                self.scan_results.insert(tk.END, 
                                    f"  Port {port_info['port']}: {port_info['service']}\n")
                    
                    # Display ping results
                    if 'ping' in scan_result:
                        self.scan_results.insert(tk.END, f"\nPing Results:\n{scan_result['ping']}\n")
                    
                    # Display location
                    if 'location' in scan_result:
                        self.scan_results.insert(tk.END, f"\nLocation Information:\n{scan_result['location']}\n")
                    
                    # Generate visualization
                    self.generate_scan_visualization(scan_result)
                    
                else:
                    self.scan_results.insert(tk.END, f"Scan failed: {scan_result.get('error', 'Unknown error')}\n")
                
                self.scan_results.see(tk.END)
                
            except Exception as e:
                self.scan_results.insert(tk.END, f"Error during scan: {str(e)}\n")
                self.scan_results.see(tk.END)
        
        # Run scan in separate thread
        threading.Thread(target=perform_scan, daemon=True).start()
    
    def generate_scan_visualization(self, scan_data: Dict):
        """Generate visualization for scan results"""
        if not self.visualizer.available:
            return
        
        # Clear previous visualization
        for widget in self.viz_canvas_frame.winfo_children():
            widget.destroy()
        
        # Create port scan chart
        if 'port_scan' in scan_data and scan_data['port_scan']['success']:
            port_data = scan_data['port_scan']
            canvas = self.visualizer.create_port_scan_chart(port_data, self.viz_canvas_frame)
            if canvas:
                canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
                
                # Add toolbar
                toolbar = NavigationToolbar2Tk(canvas, self.viz_canvas_frame)
                toolbar.update()
                canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
    
    def show_scan_visualization(self):
        """Show visualization for current scan"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please perform a scan first")
            return
        
        # Get recent scan data
        scan_data = self.db_manager.get_port_scan_for_visualization(1)
        if scan_data:
            self.generate_scan_visualization(scan_data[0])
    
    def show_port_scan_chart(self):
        """Show port scan chart in visualization tab"""
        if not self.visualizer.available:
            messagebox.showwarning("Warning", "Visualization libraries not available")
            return
        
        # Clear previous visualization
        for widget in self.viz_main_frame.winfo_children():
            widget.destroy()
        
        # Get scan data
        scan_data = self.db_manager.get_port_scan_for_visualization(5)
        
        if scan_data:
            # Create combined chart for all scans
            fig = Figure(figsize=(12, 8), dpi=100)
            ax = fig.add_subplot(111)
            
            targets = []
            port_counts = []
            
            for scan in scan_data:
                targets.append(scan['target'])
                port_counts.append(scan['total_ports'])
            
            y_pos = np.arange(len(targets))
            colors = plt.cm.plasma(np.linspace(0, 1, len(targets)))
            
            bars = ax.barh(y_pos, port_counts, color=colors, edgecolor='white')
            ax.set_yticks(y_pos)
            ax.set_yticklabels(targets)
            ax.set_xlabel('Number of Open Ports')
            ax.set_title('Recent Port Scan Results', fontsize=14, fontweight='bold')
            
            # Add value labels
            for bar, count in zip(bars, port_counts):
                width = bar.get_width()
                ax.text(width + max(port_counts)*0.01, bar.get_y() + bar.get_height()/2,
                       f'{count}', ha='left', va='center', fontweight='bold')
            
            fig.tight_layout()
            
            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, self.viz_main_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.viz_main_frame)
            toolbar.update()
            canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        else:
            label = ttk.Label(self.viz_main_frame, text="No scan data available", justify=tk.CENTER)
            label.pack(expand=True)
    
    def show_threat_distribution(self):
        """Show threat distribution chart"""
        if not self.visualizer.available:
            messagebox.showwarning("Warning", "Visualization libraries not available")
            return
        
        # Clear previous visualization
        for widget in self.viz_main_frame.winfo_children():
            widget.destroy()
        
        # Get threat data
        threat_data = self.db_manager.get_threat_data_for_visualization(24)
        
        if threat_data:
            canvas = self.visualizer.create_threat_distribution_chart(threat_data, self.viz_main_frame)
            if canvas:
                canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
                
                # Add toolbar
                toolbar = NavigationToolbar2Tk(canvas, self.viz_main_frame)
                toolbar.update()
                canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        else:
            label = ttk.Label(self.viz_main_frame, text="No threat data available", justify=tk.CENTER)
            label.pack(expand=True)
    
    def show_traffic_flow(self):
        """Show network traffic flow visualization"""
        if not self.visualizer.available:
            messagebox.showwarning("Warning", "Visualization libraries not available")
            return
        
        # Clear previous visualization
        for widget in self.viz_main_frame.winfo_children():
            widget.destroy()
        
        # Create sample traffic data (in real app, this would come from monitoring)
        traffic_data = [
            {'protocol': 'TCP', 'packet_count': 1500},
            {'protocol': 'UDP', 'packet_count': 800},
            {'protocol': 'ICMP', 'packet_count': 200},
            {'protocol': 'Other', 'packet_count': 50}
        ]
        
        canvas = self.visualizer.create_traffic_flow_chart(traffic_data, self.viz_main_frame)
        if canvas:
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.viz_main_frame)
            toolbar.update()
            canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
    
    def show_timeline(self):
        """Show timeline visualization"""
        if not self.visualizer.available:
            messagebox.showwarning("Warning", "Visualization libraries not available")
            return
        
        # Clear previous visualization
        for widget in self.viz_main_frame.winfo_children():
            widget.destroy()
        
        # Create sample timeline data
        timeline_data = []
        base_time = datetime.now()
        
        events = [
            {'event_type': 'Port Scan', 'severity': 'high'},
            {'event_type': 'Brute Force', 'severity': 'medium'},
            {'event_type': 'DDoS', 'severity': 'high'},
            {'event_type': 'Malware', 'severity': 'high'},
            {'event_type': 'Phishing', 'severity': 'low'},
        ]
        
        for i, event in enumerate(events):
            event_time = base_time - timedelta(minutes=i*30)
            event['timestamp'] = event_time.isoformat()
            timeline_data.append(event)
        
        canvas = self.visualizer.create_timeline_chart(timeline_data, self.viz_main_frame)
        if canvas:
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add toolbar
            toolbar = NavigationToolbar2Tk(canvas, self.viz_main_frame)
            toolbar.update()
            canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
    
    def show_traffic_analysis(self):
        """Alias for traffic flow"""
        self.show_traffic_flow()
    
    def show_timeline_view(self):
        """Alias for timeline"""
        self.show_timeline()
    
    def update_threat_analysis(self):
        """Update threat analysis tab"""
        try:
            # Get threat statistics
            threat_data = self.db_manager.get_threat_data_for_visualization(24)
            
            # Update statistics labels
            total = sum(t['count'] for t in threat_data)
            high = sum(t['count'] for t in threat_data if t['severity'] == 'high')
            medium = sum(t['count'] for t in threat_data if t['severity'] == 'medium')
            low = sum(t['count'] for t in threat_data if t['severity'] == 'low')
            
            self.threat_stats_labels['total'].config(text=str(total))
            self.threat_stats_labels['high'].config(text=str(high))
            self.threat_stats_labels['medium'].config(text=str(medium))
            self.threat_stats_labels['low'].config(text=str(low))
            self.threat_stats_labels['recent'].config(text=str(min(total, 20)))
            
            # Find top threat type
            if threat_data:
                top_type = max(threat_data, key=lambda x: x['count'])['threat_type']
                self.threat_stats_labels['top_type'].config(text=top_type[:15])
            
            # Update threat tree
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)
            
            # Add recent threats (simulated for now)
            sample_threats = [
                ("10:30", "192.168.1.100", "Port Scan", "High", "Multiple port connections"),
                ("11:15", "10.0.0.5", "Brute Force", "Medium", "SSH login attempts"),
                ("12:45", "203.0.113.25", "DDoS", "High", "Traffic flood detected"),
                ("14:20", "192.168.1.50", "Malware", "High", "Suspicious process"),
                ("15:10", "172.16.0.10", "Phishing", "Low", "Suspicious email source")
            ]
            
            for threat in sample_threats[:5]:
                self.threats_tree.insert('', 'end', values=threat)
            
            # Update visualizations if tab is active
            current_tab = self.notebook.index(self.notebook.select())
            if current_tab == 3:  # Threat Analysis tab
                self.update_threat_visualizations(threat_data)
                
        except Exception as e:
            print(f"Error updating threat analysis: {e}")
    
    def update_threat_visualizations(self, threat_data):
        """Update threat visualizations"""
        if not self.visualizer.available:
            return
        
        # Clear previous visualizations
        for widget in self.threat_pie_frame.winfo_children():
            widget.destroy()
        for widget in self.threat_bar_frame.winfo_children():
            widget.destroy()
        
        if threat_data:
            # Create pie chart
            pie_fig = Figure(figsize=(6, 4), dpi=100)
            pie_ax = pie_fig.add_subplot(111)
            
            # Group by threat type
            type_counts = {}
            for threat in threat_data:
                ttype = threat['threat_type']
                type_counts[ttype] = type_counts.get(ttype, 0) + threat['count']
            
            if type_counts:
                labels = list(type_counts.keys())
                sizes = list(type_counts.values())
                colors = plt.cm.tab20c(np.linspace(0, 1, len(labels)))
                
                pie_ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                pie_ax.set_title('Threat Type Distribution', fontsize=12)
                
                pie_canvas = FigureCanvasTkAgg(pie_fig, self.threat_pie_frame)
                pie_canvas.draw()
                pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Create bar chart
            bar_fig = Figure(figsize=(6, 4), dpi=100)
            bar_ax = bar_fig.add_subplot(111)
            
            # Group by severity
            severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
            for threat in threat_data:
                severity = threat['severity'].capitalize()
                if severity in severity_counts:
                    severity_counts[severity] += threat['count']
            
            severities = list(severity_counts.keys())
            counts = list(severity_counts.values())
            colors = ['#FF5252', '#FFD740', '#69F0AE']
            
            bars = bar_ax.bar(severities, counts, color=colors, edgecolor='white')
            bar_ax.set_ylabel('Count')
            bar_ax.set_title('Threat Severity Levels', fontsize=12)
            
            # Add value labels
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                bar_ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                          f'{count}', ha='center', va='bottom')
            
            bar_canvas = FigureCanvasTkAgg(bar_fig, self.threat_bar_frame)
            bar_canvas.draw()
            bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        interface = self.monitor_iface.get().strip() or None
        self.metrics_text.delete(1.0, tk.END)
        self.metrics_text.insert(tk.END, f"Starting monitoring on interface: {interface or 'default'}\n")
        
        # Simulate monitoring updates
        def monitor_thread():
            packet_count = 0
            threat_count = 0
            
            while getattr(self, 'monitoring_active', False):
                time.sleep(2)
                
                # Simulate metrics
                packet_count += random.randint(50, 200)
                threat_count += random.randint(0, 2)
                
                self.metrics_text.delete(1.0, tk.END)
                self.metrics_text.insert(tk.END, f"Real-time Metrics:\n")
                self.metrics_text.insert(tk.END, f"Packets Processed: {packet_count:,}\n")
                self.metrics_text.insert(tk.END, f"Threats Detected: {threat_count}\n")
                self.metrics_text.insert(tk.END, f"Packet Rate: {random.randint(20, 100)}/s\n")
                self.metrics_text.insert(tk.END, f"CPU Usage: {psutil.cpu_percent()}%\n")
                self.metrics_text.insert(tk.END, f"Memory Usage: {psutil.virtual_memory().percent}%\n")
                
                # Update traffic visualization periodically
                if packet_count % 100 == 0:
                    self.update_traffic_visualization()
        
        self.monitoring_active = True
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        self.metrics_text.insert(tk.END, "\nMonitoring stopped.\n")
    
    def update_traffic_visualization(self):
        """Update traffic visualization"""
        if not self.visualizer.available:
            return
        
        # Clear previous visualization
        for widget in self.traffic_viz_frame.winfo_children():
            widget.destroy()
        
        # Create sample traffic data
        protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'SMTP', 'Other']
        traffic = [random.randint(100, 1000) for _ in protocols]
        
        fig = Figure(figsize=(10, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        x_pos = np.arange(len(protocols))
        colors = plt.cm.viridis(np.linspace(0, 1, len(protocols)))
        
        bars = ax.bar(x_pos, traffic, color=colors, edgecolor='white')
        ax.set_xticks(x_pos)
        ax.set_xticklabels(protocols, rotation=45, ha='right')
        ax.set_ylabel('Packets')
        ax.set_title('Real-time Traffic by Protocol', fontsize=12)
        
        # Add value labels
        for bar, count in zip(bars, traffic):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 5,
                   f'{count}', ha='center', va='bottom', fontsize=8)
        
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, self.traffic_viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def refresh_visualizations(self):
        """Refresh all visualizations"""
        self.update_threat_analysis()
        
        # Check which tab is active and update accordingly
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 2:  # Visualization tab
            # Re-show current visualization
            # You might want to track which visualization is currently shown
            pass
        
        messagebox.showinfo("Refresh", "Visualizations refreshed")
    
    def save_chart(self):
        """Save current chart to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Get current visualization frame
                current_tab = self.notebook.index(self.notebook.select())
                
                if current_tab == 2:  # Visualization tab
                    for widget in self.viz_main_frame.winfo_children():
                        if isinstance(widget, FigureCanvasTkAgg):
                            widget.figure.savefig(file_path, dpi=300, bbox_inches='tight')
                            messagebox.showinfo("Success", f"Chart saved to {file_path}")
                            return
                
                messagebox.showwarning("Warning", "No active chart to save")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save chart: {str(e)}")
    
    def export_viz_data(self):
        """Export visualization data to JSON"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Get visualization data
                scan_data = self.db_manager.get_port_scan_for_visualization(10)
                threat_data = self.db_manager.get_threat_data_for_visualization(24)
                
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'scans': scan_data,
                    'threats': threat_data,
                    'system_info': {
                        'hostname': socket.gethostname(),
                        'platform': platform.platform(),
                        'python_version': sys.version
                    }
                }
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def quick_scan(self):
        """Perform quick scan on local network"""
        self.target_entry.delete(0, tk.END)
        
        # Get local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Set to scan local subnet
            base_ip = '.'.join(local_ip.split('.')[:3])
            target = f"{base_ip}.1"
            self.target_entry.insert(0, target)
            
            self.start_scan()
        except:
            messagebox.showerror("Error", "Could not determine local IP")
    
    def show_threats(self):
        """Show threat analysis tab"""
        self.notebook.select(3)  # Threat Analysis tab
    
    def generate_report(self):
        """Generate comprehensive report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cyber_defense_report_{timestamp}.txt"
            filepath = os.path.join(REPORT_DIR, filename)
            
            os.makedirs(REPORT_DIR, exist_ok=True)
            
            with open(filepath, 'w') as f:
                f.write("="*60 + "\n")
                f.write("ACCURATE CYBER DEFENSE REPORT\n")
                f.write("="*60 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Tool Version: {VERSION}\n\n")
                
                # System information
                f.write("SYSTEM INFORMATION:\n")
                f.write("-"*40 + "\n")
                f.write(f"Hostname: {socket.gethostname()}\n")
                f.write(f"Platform: {platform.platform()}\n")
                f.write(f"Python: {sys.version}\n\n")
                
                # Network information
                f.write("NETWORK STATUS:\n")
                f.write("-"*40 + "\n")
                try:
                    f.write(f"Local IP: {socket.gethostbyname(socket.gethostname())}\n")
                except:
                    f.write("Local IP: Unknown\n")
                
                f.write("\nRECOMMENDATIONS:\n")
                f.write("-"*40 + "\n")
                f.write("1. Regularly update security patches\n")
                f.write("2. Monitor network traffic for anomalies\n")
                f.write("3. Conduct regular vulnerability assessments\n")
                f.write("4. Implement strong authentication mechanisms\n")
                f.write("5. Keep backups of critical data\n")
            
            messagebox.showinfo("Report Generated", f"Report saved to:\n{filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def open_terminal(self):
        """Open terminal window"""
        terminal_window = tk.Toplevel(self.root)
        terminal_window.title("Cyber Defense Terminal")
        terminal_window.geometry("800x500")
        
        terminal_text = scrolledtext.ScrolledText(terminal_window, wrap=tk.WORD)
        terminal_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        input_frame = tk.Frame(terminal_window)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text=">").pack(side=tk.LEFT)
        terminal_input = tk.Entry(input_frame)
        terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        def execute_command(event=None):
            command = terminal_input.get()
            terminal_input.delete(0, tk.END)
            
            if not command:
                return
            
            terminal_text.insert(tk.END, f"> {command}\n")
            
            # Execute command
            try:
                if command.lower() == 'help':
                    help_text = """
Available Commands:
  scan <ip>            - Scan target IP
  ping <ip>            - Ping target
  traceroute <target>  - Trace route to target
  clear                - Clear terminal
  exit                 - Close terminal
                    """
                    terminal_text.insert(tk.END, help_text + "\n")
                elif command.lower().startswith('scan '):
                    target = command[5:].strip()
                    terminal_text.insert(tk.END, f"Scanning {target}...\n")
                    # Simulate scan
                    time.sleep(1)
                    terminal_text.insert(tk.END, f"Scan completed for {target}\n")
                elif command.lower().startswith('ping '):
                    target = command[5:].strip()
                    terminal_text.insert(tk.END, f"Pinging {target}...\n")
                    # Simulate ping
                    time.sleep(0.5)
                    terminal_text.insert(tk.END, f"Reply from {target}: time=10ms\n")
                elif command.lower() == 'clear':
                    terminal_text.delete(1.0, tk.END)
                elif command.lower() == 'exit':
                    terminal_window.destroy()
                else:
                    terminal_text.insert(tk.END, f"Unknown command: {command}\n")
            except Exception as e:
                terminal_text.insert(tk.END, f"Error: {str(e)}\n")
            
            terminal_text.see(tk.END)
        
        terminal_input.bind('<Return>', execute_command)
        tk.Button(input_frame, text="Execute", command=execute_command).pack(side=tk.RIGHT)
    
    def new_scan(self):
        """Clear scan fields for new scan"""
        self.target_entry.delete(0, tk.END)
        self.scan_results.delete(1.0, tk.END)
        
        # Clear visualization
        for widget in self.viz_canvas_frame.winfo_children():
            widget.destroy()
        
        placeholder = ttk.Label(self.viz_canvas_frame, text="Visualization will appear here\nafter scan completion", 
                               justify=tk.CENTER)
        placeholder.pack(expand=True)
    
    def save_visualization(self):
        """Save current visualization"""
        self.save_chart()
    
    def export_report(self):
        """Export comprehensive report"""
        self.generate_report()
    
    def update_dashboard(self):
        """Update dashboard information"""
        # Update threat analysis
        self.update_threat_analysis()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)

class NetworkManager:
    """Central network management for all networking commands"""
    
    def __init__(self):
        self.db_manager = EnhancedDatabaseManager()
        self.scanner = EnhancedNetworkScanner(self.db_manager)
    
    def execute_network_command(self, command: str, args: List[str]) -> str:
        """Execute network-related commands"""
        if command == "ping":
            if not args:
                return "Usage: ping <ip/hostname>"
            return self.scanner.ping_ip(args[0])
        
        elif command == "scan":
            if not args:
                return "Usage: scan <ip> [ports]"
            
            target = args[0]
            ports = args[1] if len(args) > 1 else "1-1000"
            
            result = self.scanner.port_scan(target, ports)
            if result['success']:
                response = f"Scan Results for {target}:\n"
                response += f"Open Ports: {result.get('total_open', 0)}\n\n"
                
                for port_info in result.get('open_ports', [])[:15]:
                    response += f"Port {port_info['port']}: {port_info['service']}\n"
                    if port_info.get('version'):
                        response += f"  Version: {port_info['version']}\n"
                
                if result.get('total_open', 0) > 15:
                    response += f"\n... and {result['total_open'] - 15} more ports"
                
                return response
            else:
                return f"Scan failed: {result.get('error', 'Unknown error')}"
        
        elif command == "traceroute":
            if not args:
                return "Usage: traceroute <target>"
            
            target = args[0]
            try:
                if platform.system() == "Windows":
                    cmd = ["tracert", "-d", target]
                else:
                    if shutil.which('traceroute'):
                        cmd = ["traceroute", "-n", "-q", "1", "-w", "2", target]
                    elif shutil.which('tracepath'):
                        cmd = ["tracepath", target]
                    else:
                        cmd = ["ping", "-c", "4", target]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return f"Traceroute to {target}:\n\n{result.stdout}"
                
            except Exception as e:
                return f"Traceroute error: {str(e)}"
        
        elif command == "nslookup":
            if not args:
                return "Usage: nslookup <domain>"
            
            domain = args[0]
            try:
                if platform.system() == "Windows":
                    cmd = ["nslookup", domain]
                else:
                    cmd = ["dig", domain, "+short"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return f"DNS Lookup for {domain}:\n\n{result.stdout}"
            except Exception as e:
                return f"DNS lookup error: {str(e)}"
        
        elif command == "whois":
            if not args:
                return "Usage: whois <domain>"
            
            domain = args[0]
            try:
                cmd = ["whois", domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return f"WHOIS for {domain}:\n\n{result.stdout[:1000]}..."
            except Exception as e:
                return f"WHOIS lookup error: {str(e)}"
        
        elif command == "ifconfig" or command == "ipconfig":
            try:
                if platform.system() == "Windows":
                    cmd = ["ipconfig", "/all"]
                else:
                    cmd = ["ifconfig", "-a"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return f"Network Configuration:\n\n{result.stdout}"
            except Exception as e:
                return f"Network config error: {str(e)}"
        
        elif command == "netstat":
            try:
                if platform.system() == "Windows":
                    cmd = ["netstat", "-ano"]
                else:
                    cmd = ["netstat", "-tulpn"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return f"Network Statistics:\n\n{result.stdout}"
            except Exception as e:
                return f"Netstat error: {str(e)}"
        
        elif command == "route":
            try:
                if platform.system() == "Windows":
                    cmd = ["route", "print"]
                else:
                    cmd = ["route", "-n"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return f"Routing Table:\n\n{result.stdout}"
            except Exception as e:
                return f"Route command error: {str(e)}"
        
        else:
            return f"Unknown network command: {command}"

def print_banner():
    """Print enhanced banner"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║           🛡️  ACCURATE CYBER DRILL TOOL v{VERSION} WITH VISUALIZATION  🛡️      ║
║                                                                                  ║
║      Network Monitoring • Intrusion Detection • Advanced Visualization           ║
║         Security Analysis • Threat Detection • Real-time Analytics               ║
║                    Data Charts • Network Graphs • Comprehensive Reports          ║
║                                                                                  ║
║   Author: Ian Carter Kulani              Community: Accurate Cyber Defense       ║
║   Features: Port Scanning, Deep Analysis, Kill Mode, Location Lookup            ║
║             Bar Charts, Pie Charts, Timeline Visualizations, Real-time Metrics   ║
║                                                                                  ║
║   Key Features:                                                                  ║
║   • Real-time Network Monitoring      • Advanced Threat Detection                ║
║   • Port & Vulnerability Scanning     • Traffic Generation Tools                 ║
║   • Intrusion Detection System        • Comprehensive Reporting                  ║
║   • CLI & GUI Interfaces              • Data Visualization (Charts & Graphs)     ║
║   • Deep IP Analysis                  • Geographical Location Lookup             ║
║   • Kill Mode (Stress Testing)        • Database Logging & Analytics             ║
║   • Real-time Visualizations          • Export Reports & Charts                  ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def run_gui_mode():
    """Run GUI mode"""
    if not GUI_AVAILABLE:
        print(f"{Colors.RED}❌ GUI mode requires tkinter. Please install it or use CLI mode.{Colors.END}")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On Fedora/RHEL: sudo dnf install python3-tkinter")
        print("On macOS: brew install python-tk")
        print("On Windows: Usually included with Python")
        return 'cli'
    
    if not MATPLOTLIB_AVAILABLE:
        print(f"{Colors.YELLOW}⚠️  Visualization features require matplotlib, seaborn, pandas{Colors.END}")
        print("Install with: pip install matplotlib seaborn pandas numpy")
        print("Basic GUI will work, but charts will be disabled.")
    
    root = tk.Tk()
    db_manager = EnhancedDatabaseManager()
    scanner = EnhancedNetworkScanner(db_manager)
    
    try:
        app = CyberDefenseGUI(root, db_manager, scanner)
        root.mainloop()
        return 'menu'
    except Exception as e:
        print(f"{Colors.RED}GUI Error: {e}{Colors.END}")
        return 'cli'

def run_cli_mode():
    """Run CLI mode"""
    network_manager = NetworkManager()
    
    print_banner()
    print(f"\n{Colors.GREEN}🔧 Enhanced CLI Mode with Visualization Support{Colors.END}")
    print("Type 'help' for available commands")
    print("Type 'gui' to switch to GUI mode")
    print("Type 'exit' to quit\n")
    
    while True:
        try:
            command = input(f"{Colors.GREEN}cyberdefense>{Colors.END} ").strip()
            if not command:
                continue
            
            if command.lower() == 'exit':
                print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                break
            
            elif command.lower() == 'gui':
                print(f"{Colors.CYAN}🚀 Switching to GUI mode...{Colors.END}")
                return 'gui'
            
            elif command.lower() == 'help':
                help_text = f"""{Colors.CYAN}Available Commands:{Colors.END}

{Colors.GREEN}Network Commands:{Colors.END}
  ping <ip/hostname>          - Ping a target
  scan <ip> [ports]           - Port scan (default: 1-1000)
  traceroute <target>         - Trace route to target
  nslookup <domain>           - DNS lookup
  whois <domain>              - WHOIS lookup
  ifconfig/ipconfig           - Network configuration
  netstat                     - Network statistics
  route                       - Routing table

{Colors.GREEN}System Commands:{Colors.END}
  help                        - Show this help
  clear                       - Clear screen
  exit                        - Exit program
  gui                         - Switch to GUI mode

{Colors.YELLOW}Examples:{Colors.END}
  ping 8.8.8.8
  scan 192.168.1.1 1-100
  traceroute google.com
  nslookup example.com
                """
                print(help_text)
            
            elif command.lower() == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            
            else:
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                result = network_manager.execute_network_command(cmd, args)
                if result:
                    print(result)
                else:
                    print(f"Unknown command: {cmd}")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")

def main():
    """Main entry point"""
    print_banner()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cyber_security.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cli':
            mode = 'cli'
        elif sys.argv[1] == '--gui':
            mode = 'gui'
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python cyber_tool.py [--cli|--gui]")
            mode = 'menu'
    else:
        # Interactive mode selection
        print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
        print("  1. CLI Mode (Command Line Interface)")
        print("  2. GUI Mode (Graphical User Interface with Visualization)")
        print("  3. Exit")
        
        while True:
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
                break
            elif choice == '2':
                mode = 'gui'
                break
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                return
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
    
    # Run selected mode
    while True:
        if mode == 'cli':
            mode = run_cli_mode()
        elif mode == 'gui':
            mode = run_gui_mode()
        elif mode == 'menu':
            print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
            print("  1. CLI Mode (Command Line Interface)")
            print("  2. GUI Mode (Graphical User Interface)")
            print("  3. Exit")
            
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
            elif choice == '2':
                mode = 'gui'
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Application error: {e}{Colors.END}")
        logging.exception("Application crash")