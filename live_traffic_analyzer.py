# This script connects to a Bettercap instance for live traffic analysis.
# Before running this, ensure you have executed './bettercap_auto.sh' with root privileges
# to start the Bettercap API service.

import websockets
import json
import re
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
from termcolor import colored
import signal
import sys
import os

REPORTS_FILE = 'reports.json'
STATS_FILE = 'network_stats.json'
WHITELIST_FILE = 'whitelist.json'

class SecurityAnalyzer:
    def __init__(self):
        """Initialize the analyzer"""
        self._load_config()
        self._setup_trackers()
        self.running = True
        self.whitelist = []
        self._load_whitelist()
        self._initialize_reports_file()
        self._initialize_stats_file()
        self.last_stats_save = datetime.now()
        self.handlers = {
            "net.sniff": self._analyze_network_packet,
            "net.recon.new": self._handle_new_device,
            "endpoint.new": self._update_device_info,
            "endpoint.updated": self._update_device_info,
            "endpoint.lost": self._remove_device_info,
            "wifi.client.new": self._update_device_info,
            "wifi.client.lost": self._remove_device_info,
            "wifi.ap.new": self._analyze_wifi_ap,
            "wifi.deauthentication": self._check_deauth_attack,
        }

    def _setup_trackers(self):
        """Initialize all tracking data structures"""
        self.device_stats = defaultdict(lambda: defaultdict(int))
        self.ip_to_mac = {}
        self.device_info = defaultdict(dict)
        self.syn_count = deque(maxlen=1000)
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.icmp_tracker = defaultdict(int)
        self.deauth_tracker = defaultdict(lambda: {
            'count': 0,
            'timestamps': deque(maxlen=50),
            'clients': set()
        })
        self.client_reconnect_times = defaultdict(list)
        self.rogue_ap_tracker = defaultdict(dict)

    def _load_config(self):
        """Load security thresholds and configuration"""
        self.SECURITY_THRESHOLDS = {
            'syn_flood': {'threshold': 100, 'window': timedelta(seconds=10)},
            'port_scan': {'unique_ports': 20, 'window': timedelta(minutes=1)},
            'ping_sweep': {'icmp_count': 50, 'window': timedelta(minutes=1)},
            'deauth_attack': {
                'frame_threshold': 10,
                'window': timedelta(seconds=30),
                'reconnect_threshold': 2.0
            },
            'rogue_ap': {
                'similar_ssid_threshold': 0.8,
                'monitor_window': timedelta(minutes=5)
            }
        }
        self.known_aps = {'00:11:22:33:44:55'}
        self.trusted_devices = {'aa:bb:cc:dd:ee:ff'}
        self.PORT_MAP = {
            'Browsing': {'TCP': {80, 443}},
            'Streaming': {'TCP': {1935, 554, 1755, 8080}, 'UDP': {1935, 554, 1755, 8080}},
            'VoIP': {'UDP': set(range(5004, 5006)) | {5060, 5061, 3478} | set(range(10000, 20001))},
            'File Transfer': {'TCP': {20, 21, 22, 989, 990}},
            'Gaming': {'UDP': {3074, 27015, 25565} | set(range(3478, 3481))},
            'Email': {'TCP': {25, 110, 143, 465, 587, 993, 995}},
            'Remote Desktop': {'TCP': {3389, 5900}},
            'VPN': {'TCP': {1194}, 'UDP': {1194, 1701, 500, 4500}},
            'Cloud/Sync': {'TCP': {443, 5222, 5228, 8883}, 'UDP': {443, 5222, 5228, 8883}},
            'Network Service': {'UDP': {5353, 137, 138}},
        }

    def _handle_shutdown(self):
        """Graceful shutdown handler that generates a report before exiting."""
        if self.running:
            print(colored("\n[*] Generating final traffic report...", "yellow"))
            self._generate_traffic_report()
            self.running = False

    async def analyze_traffic(self):
        """Main analysis loop connecting to Bettercap with URL-based authentication."""
        url = f"ws://darkbert:20231405@localhost:8081/api/events"
        while self.running:
            try:
                async with websockets.connect(url, ping_timeout=30, close_timeout=10) as ws:
                    print(colored("[+] Connected to Bettercap API", "green"))
                    await self._event_loop(ws)
            except ConnectionRefusedError:
                print(colored("\n[-] Connection to Bettercap was refused.", "red"))
                print(colored("    Please ensure Bettercap is running and the API is accessible.", "yellow"))
            except websockets.exceptions.InvalidURI:
                print(colored(f"\n[-] Invalid WebSocket URL: {url}", "red"))
            except websockets.exceptions.WebSocketException as e:
                print(colored(f"\n[-] A WebSocket error occurred: {e}", "red"))
            except Exception as e:
                print(colored(f"\n[-] An unexpected error occurred in analyze_traffic: {e}", "red"))
            finally:
                if self.running:
                    await asyncio.sleep(5)

    def _load_whitelist(self):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                data = json.load(f)
                self.whitelist = data.get("authorized_macs", [])
            print(colored(f"[*] Successfully loaded {len(self.whitelist)} devices from whitelist.", "green"))
        except FileNotFoundError:
            print(colored("[*] Whitelist file not found. All devices will be considered unauthorized.", "yellow"))
            self.whitelist = []
        except json.JSONDecodeError:
            print(colored("[-] Error reading whitelist file. It might be corrupted.", "red"))
            self.whitelist = []

    def _initialize_stats_file(self):
        if not os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'w') as f:
                json.dump({}, f)

    def _save_network_stats(self):
        aggregated_traffic = defaultdict(int)
        for mac, stats in self.device_stats.items():
            for traffic_type, byte_count in stats.items():
                if traffic_type not in ['total_bytes', 'total_packets', 'ip']:
                    aggregated_traffic[traffic_type] += byte_count

        all_macs = list(self.device_stats.keys())
        authorized_devices = []
        unauthorized_devices = []

        for mac in all_macs:
            device_details = {
                'mac': mac,
                'ip': self.device_info.get(mac, {}).get('ip', 'N/A'),
                'hostname': self.device_info.get(mac, {}).get('hostname', 'N/A')
            }
            if mac in self.whitelist:
                authorized_devices.append(device_details)
            else:
                unauthorized_devices.append(device_details)

        stats_data = {
            'traffic_distribution': dict(aggregated_traffic),
            'device_count': len(all_macs),
            'authorized_devices': authorized_devices,
            'unauthorized_devices': unauthorized_devices,
            'last_updated': datetime.now().isoformat()
        }

        try:
            with open(STATS_FILE, 'w') as f:
                json.dump(stats_data, f, indent=4)
        except IOError as e:
            print(colored(f"[-] Error writing stats file: {e}", "red"))

    async def _event_loop(self, ws):
        """Process incoming WebSocket events"""
        print(colored("[*] Ensuring net.sniff module is running...", "blue"))
        await ws.send(json.dumps({"request": "session.command", "data": "net.sniff on"}))

        print(colored("[*] Subscribing to Bettercap event stream...", "blue"))
        await ws.send(json.dumps({"subscribe": "*"}))

        while self.running:
            try:
                message = await asyncio.wait_for(ws.recv(), timeout=2.0)
                event = json.loads(message)
                self._process_event(event)
            except asyncio.TimeoutError:
                pass  # No new events, just an opportunity to save stats
            except json.JSONDecodeError:
                continue
            except websockets.exceptions.ConnectionClosed:
                print(colored("[-] Connection to Bettercap closed.", "red"))
                break
            except Exception as e:
                print(colored(f"[-] Error processing event: {e}", "red"))

            # Periodically save stats
            if datetime.now() - self.last_stats_save > timedelta(seconds=2):
                print(colored("[*] Saving network stats...", "blue"))
                self._save_network_stats()
                self.last_stats_save = datetime.now()

    def _initialize_reports_file(self):
        if not os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, 'w') as f:
                json.dump([], f)

    def _save_report(self, report):
        with open(REPORTS_FILE, 'r+') as f:
            reports = json.load(f)
            reports.append(report)
            f.seek(0)
            json.dump(reports, f, indent=4)
            f.truncate()

    def _process_event(self, event):
        """Route incoming websocket events to the correct handler and save reports."""
        event_tag = event.get("tag")
        if not event_tag or "data" not in event:
            return

        # Save security-related events as reports
        if not event_tag.startswith("net.sniff"):
            report = {
                'id': event.get('id', str(datetime.now())),
                'date': datetime.now().isoformat(),
                'type': event_tag,
                'source_ip': event.get('data', {}).get('ip') or event.get('data', {}).get('hostname', 'N/A'),
                'details': event.get('data', {})
            }
            self._save_report(report)

        # Route event to its handler
        handler_func = self.handlers.get(event_tag)
        if handler_func:
            handler_func(event["data"])
            return

        if event_tag.startswith("net.sniff"):
            handler_func = self.handlers.get("net.sniff")
            if handler_func:
                handler_func(event["data"])

    def _update_device_info(self, data):
        """Update device IP-MAC mapping and hostname from endpoint or wifi events."""
        mac = data.get("mac")
        ip = data.get("ip")
        hostname = data.get("hostname")
        if mac:
            if ip:
                self.ip_to_mac[ip] = mac
                self.device_info[mac]['ip'] = ip
            if hostname:
                self.device_info[mac]['hostname'] = hostname

    def _remove_device_info(self, data):
        """Remove device info when an endpoint is lost."""
        mac = data.get("mac")
        ip = data.get("ip")
        mac_to_remove = mac
        if not mac_to_remove and ip and ip in self.ip_to_mac:
            mac_to_remove = self.ip_to_mac.pop(ip, None)

        if mac_to_remove:
            if mac_to_remove in self.device_info:
                del self.device_info[mac_to_remove]
            print(colored(f"[-] Device Lost: {mac_to_remove} (IP: {ip or 'N/A'})", "yellow"))

    def _classify_packet(self, proto, dport):
        """Classify traffic based on protocol and destination port."""
        proto_str = {6: 'TCP', 17: 'UDP'}.get(proto)
        if not proto_str:
            return 'Other'
        for traffic_type, ports in self.PORT_MAP.items():
            if proto_str in ports and dport in ports[proto_str]:
                return traffic_type
        return 'Other'

    def _parse_address(self, address_str):
        """Parses an address string that might contain a port or service name."""
        if not isinstance(address_str, str):
            return None, -1

        # Clean up terminal color codes
        address_str = re.sub(r'\x1b\[[0-9;]*m', '', address_str)

        # Common service name to port mapping
        service_ports = {'https': 443, 'http': 80, 'mdns': 5353, 'netbios-ns': 137}

        # Handle IPv6 with brackets, e.g., [fe80::...]:54321
        match = re.match(r'\[(.*)\]:(\d+)', address_str)
        if match:
            return match.group(1), int(match.group(2))

        # Handle IPv4/IPv6 with port or service name by splitting from the right
        parts = address_str.rsplit(':', 1)
        if len(parts) == 2:
            ip, port_or_service = parts
            # This check helps distinguish hostnames from IPv6 addresses
            if '.' in ip or '::' in ip or ip.count(':') > 1:
                if port_or_service.isdigit():
                    return ip, int(port_or_service)
                elif port_or_service in service_ports:
                    return ip, service_ports[port_or_service]

        # Fallback for address without port or unhandled format
        return address_str, -1

    def _analyze_network_packet(self, packet):
        """Analyze and classify traffic, print summary, and update stats."""
        # --- Data Extraction ---
        src_ip_raw = packet.get("from") or packet.get("src_ip")
        dst_ip_raw = packet.get("to") or packet.get("dst_ip")

        src_ip, _ = self._parse_address(src_ip_raw)
        dst_ip, dport_from_addr = self._parse_address(dst_ip_raw)

        # Use the newly populated ip_to_mac for robust MAC resolution
        src_mac = packet.get("src_mac") or self.ip_to_mac.get(src_ip)
        dst_mac = packet.get("dst_mac") or self.ip_to_mac.get(dst_ip)

        proto_name = packet.get("protocol") or packet.get("proto")
        proto = -1
        if isinstance(proto_name, str):
            proto = {'tcp': 6, 'udp': 17}.get(proto_name.lower(), -1)
        elif isinstance(proto_name, int):
            proto = proto_name

        # Prioritize explicit port fields from bettercap
        dport = packet.get("dport") or packet.get("dst_port")
        if not isinstance(dport, int) or dport <= 0:
            dport = dport_from_addr # Fallback to parsed port

        size = packet.get("len", 0)

        # --- Classification and Output ---
        traffic_type = "Other"
        if dport > 0 and proto != -1:
            traffic_type = self._classify_packet(proto, dport)

        print(
            f"{colored('[TRAFFIC]', 'cyan')} "
            f"SRC IP: {colored(str(src_ip), 'yellow'):<25} MAC: {colored(str(src_mac or 'N/A'), 'yellow'):<18} | "
            f"DST IP: {colored(str(dst_ip), 'magenta'):<25} MAC: {colored(str(dst_mac or 'N/A'), 'magenta'):<18} | "
            f"PORT: {colored(str(dport), 'blue'):<5} | "
            f"Type: {colored(traffic_type, 'green')}"
        )

        # --- Stats Aggregation ---
        if traffic_type != "Other":
            if src_mac and src_mac in self.device_stats:
                self.device_stats[src_mac]['total_packets'] += 1
                self.device_stats[src_mac]['total_bytes'] += size
                self.device_stats[src_mac][traffic_type] += size

            if dst_mac and dst_mac != src_mac and dst_mac in self.device_stats:
                self.device_stats[dst_mac]['total_packets'] += 1
                self.device_stats[dst_mac]['total_bytes'] += size
                self.device_stats[dst_mac][traffic_type] += size

    def _handle_new_device(self, device_data):
        """Handles new device discovery events to map IPs to MACs."""
        ip = device_data.get('ip')
        mac = device_data.get('mac')
        if ip and mac:
            if self.ip_to_mac.get(ip) != mac:
                print(f"{colored('[RECON]', 'blue')} New device seen: IP: {colored(ip, 'yellow')}, MAC: {colored(mac, 'yellow')}")
                self.ip_to_mac[ip] = mac
            
            if mac not in self.device_stats:
                self.device_stats[mac] = {
                    'ip': ip,
                    'total_packets': 0,
                    'total_bytes': 0,
                    **{cat: 0 for cat in self.PORT_MAP.keys()}
                }

    def _analyze_wifi_ap(self, data):
        """Placeholder for analyzing WiFi APs for security threats."""
        pass

    def _check_deauth_attack(self, data):
        """Placeholder for detecting deauthentication attacks."""
        pass

    def _generate_traffic_report(self):
        """Generates a detailed, human-readable traffic classification report."""
        print("\n" + "="*70)
        print(colored("--- Heuristic Traffic Classification Report ---", "cyan", attrs=["bold"]))
        print("="*70)

        if not self.device_stats:
            print(colored("No traffic was captured for classified devices.", "yellow"))
            print("="*70)
            return

        sorted_devices = sorted(self.device_stats.items(), key=lambda item: item[1]['total_bytes'], reverse=True)

        for mac, stats in sorted_devices:
            info = self.device_info.get(mac, {})
            ip = info.get('ip', 'N/A')
            hostname = info.get('hostname', 'N/A')
            total_bytes = stats.get('total_bytes', 0)

            print(colored(f"\nDevice: {mac}", "white", attrs=["bold"]))
            print(f"  ├─ IP Address: {ip}")
            print(f"  ├─ Hostname:   {hostname}")
            print(f"  └─ Traffic Breakdown (Total: {total_bytes / 1024:.2f} KB):")

            if total_bytes > 0:
                traffic_stats = {k: v for k, v in stats.items() if k not in ['total_bytes', 'total_packets'] and v > 0}
                sorted_traffic = sorted(traffic_stats.items(), key=lambda item: item[1], reverse=True)

                if not sorted_traffic:
                    print("    └─ No classified traffic recorded.")
                    continue

                for i, (traffic_type, byte_count) in enumerate(sorted_traffic):
                    percentage = (byte_count / total_bytes) * 100
                    bar = "└─" if i == len(sorted_traffic) - 1 else "├─"
                    print(f"    {bar} {traffic_type:<15}: {byte_count:>8} bytes ({percentage:6.2f}%)")
            else:
                print("    └─ No traffic recorded.")
        
        print("\n" + "="*70)


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    try:
        print(colored("Starting Live Targeted Security Analyzer...", "green"))
        print(colored("Press Ctrl+C to stop and generate a report.", "blue"))
        asyncio.run(analyzer.analyze_traffic())
    except KeyboardInterrupt:
        # This block is expected to be hit on Ctrl+C.
        pass
    finally:
        analyzer._handle_shutdown()
        print(colored("\nShutdown complete. Exiting.", "green"))
