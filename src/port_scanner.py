import socket
import random
import time
import json
import csv
import logging
import argparse
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Template
from queue import Queue
from threading import Semaphore
from tqdm import tqdm
import ssl
import os
import re

# --- Configuration ---
MAX_THREADS = 50
BASE_DELAY = 0.05
TARGETS_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../examples/targets_config.json')
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024

# --- Adaptive Timeout ---
target_timeouts = {}
initial_timeout = 1.0
timeout_increase_factor = 1.5
max_timeout = 5.0

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Error Tracking ---
scan_errors = {
    'timeouts': 0,
    'failed_connections': 0,
    'other_errors': 0
}

# --- Helper Functions ---
def load_targets_config(file_path):
    """Load targets and their specific configs from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)
            targets = config.get('targets', [])
            if not targets:
                logging.error("No targets found in configuration file.")
            return targets
    except FileNotFoundError:
        logging.error(f"Targets config file '{file_path}' not found.")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error in targets config: {e}")
        return []

def get_delay():
    """Randomized delay for stealth."""
    return BASE_DELAY * random.uniform(0.5, 1.5)

def identify_service(port, banner):
    banner_lower = (banner or '').lower()
    services = {
        'http': 'HTTP',
        'ssh': 'SSH',
        'ftp': 'FTP',
        'smtp': 'SMTP',
        'pop3': 'POP3',
        'imap': 'IMAP',
        'mysql': 'MySQL',
        'postgres': 'PostgreSQL',
        'redis': 'Redis',
        'ntp': 'NTP',
        'snmp': 'SNMP'
    }
    for key in services:
        if key in banner_lower:
            return services[key]
    if port == 22:
        return 'SSH'
    elif port in (80, 443):
        return 'HTTP'
    elif port == 21:
        return 'FTP'
    elif port == 25:
        return 'SMTP'
    elif port == 53:
        return 'DNS'
    elif port == 3306:
        return 'MySQL'
    elif port == 5432:
        return 'PostgreSQL'
    return 'Unknown or Banner Not Detected'

def parse_dns_response(data):
    if data and len(data) > 12:
        response_code = data[3] & 0x0F
        if response_code == 0:
            return "DNS"
    return "Unknown"

def ping_host(target):
    try:
        count_param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.check_output(['ping', count_param, '1', target], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logging.warning(f"Ping failed for {target}: {e}")
        return False

def check_ssl_port(target, port, args):
    if not args.ssl_check:
        return False
    try:
        family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(target_timeouts.get(target, initial_timeout))
        if args.ipv6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.V6_ONLY, 0)
        sock.connect((target, port))
        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock, server_hostname=target)
        ssock.close()
        logging.info(f"[SECURE][TCP] {target}:{port} - SSL/TLS handshake successful")
        return True
    except Exception as e:
        logging.debug(f"SSL check failed for {target}:{port} - {e}")
        return False

def scan_tcp_port(target, port, current_timeout, retries=3, args=None):
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    for attempt in range(retries):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                if args.ipv6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.V6_ONLY, 0)
                sock.settimeout(current_timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    ssl_detected = False
                    if port in (443, 465, 993, 995) and args.ssl_check:
                        ssl_detected = check_ssl_port(target, port, args)
                    banner = "No banner"
                    try:
                        sock.sendall(b'\r\n')
                        banner_bytes = sock.recv(1024)
                        banner = banner_bytes.decode(errors='ignore').strip()
                    except Exception:
                        pass
                    service = identify_service(port, banner)
                    if ssl_detected:
                        service = f"SSL/{service}"
                    logging.info(f"[OPEN][TCP] {target}:{port} - Service: {service} - Banner: {banner}")
                    old_timeout = target_timeouts.get(target, initial_timeout)
                    new_timeout = max(initial_timeout, old_timeout / timeout_increase_factor)
                    target_timeouts[target] = new_timeout
                    return {
                        'target': target,
                        'port': port,
                        'protocol': 'TCP',
                        'service': service,
                        'banner': banner,
                        'status': 'open',
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                        'timeout_used': current_timeout,
                        'retries': attempt + 1
                    }
                else:
                    old_timeout = target_timeouts.get(target, initial_timeout)
                    new_timeout = min(max_timeout, old_timeout * timeout_increase_factor)
                    target_timeouts[target] = new_timeout
                    if attempt < retries - 1:
                        time.sleep(get_delay())
                    continue
        except socket.timeout:
            scan_errors['timeouts'] += 1
            logging.error(f"[TIMEOUT][TCP] {target}:{port} (Attempt {attempt + 1}/{retries})")
            return None
        except socket.error:
            scan_errors['failed_connections'] += 1
            logging.error(f"[ERROR][TCP] {target}:{port} - Connection failed (Attempt {attempt + 1}/{retries})")
            return None
        except Exception as e:
            scan_errors['other_errors'] += 1
            logging.error(f"[ERROR][TCP] {target}:{port} - {e} (Attempt {attempt + 1}/{retries})")
            return None
    logging.info(f"[CLOSED][TCP] {target}:{port} after {retries} retries")
    return {
        'target': target,
        'port': port,
        'protocol': 'TCP',
        'service': None,
        'banner': None,
        'status': 'closed',
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'timeout_used': current_timeout,
        'retries': retries
    }

def scan_udp_port(target, port, current_timeout, retries=3, args=None):
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    for attempt in range(retries):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(current_timeout)
                if port == 53:
                    sock.sendto(b'\x00\x00\x00\x00', (target, port))
                elif port == 123:
                    sock.sendto(b'\x1b' + 47 * b'\0', (target, port))
                elif port == 161:
                    sock.sendto(b'\x30\x1e\x02\x01\x00\x04\x00\x30\x1a\x30\x18\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00', (target, port))
                else:
                    sock.sendto(b'', (target, port))
                response, _ = sock.recvfrom(1024)
                service = parse_dns_response(response) if port == 53 else "Unknown"
                logging.info(f"[OPEN][UDP] {target}:{port} - Service: {service}")
                old_timeout = target_timeouts.get(target, initial_timeout)
                new_timeout = max(initial_timeout, old_timeout / timeout_increase_factor)
                target_timeouts[target] = new_timeout
                return {
                    'target': target,
                    'port': port,
                    'protocol': 'UDP',
                    'service': service,
                    'banner': None,
                    'status': 'open',
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'timeout_used': current_timeout,
                    'retries': attempt + 1
                }
        except socket.timeout:
            scan_errors['timeouts'] += 1
            logging.error(f"[TIMEOUT][UDP] {target}:{port} (Attempt {attempt + 1}/{retries})")
            return None
        except socket.error:
            scan_errors['failed_connections'] += 1
            logging.error(f"[ERROR][UDP] {target}:{port} - Connection failed (Attempt {attempt + 1}/{retries})")
            return None
        except Exception as e:
            scan_errors['other_errors'] += 1
            logging.error(f"[ERROR][UDP] {target}:{port} - {e} (Attempt {attempt + 1}/{retries})")
            return None
    logging.info(f"[CLOSED][UDP] {target}:{port} after {retries} retries")
    return {
        'target': target,
        'port': port,
        'protocol': 'UDP',
        'service': None,
        'banner': None,
        'status': 'closed',
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'timeout_used': current_timeout,
        'retries': retries
    }

def save_html_report(results, html_report_file):
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enhanced Scan Results</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f7f8; color: #333; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #2980b9; color: white; cursor: pointer; }
        tr:nth-child(even) { background-color: #ecf0f1; }
        tr:hover { background-color: #d1dbe5; }
        .open { color: green; font-weight: bold; }
        .closed { color: red; font-weight: bold; }
        .summary { margin-bottom: 20px; padding: 15px; background: #3498db; color: white; border-radius: 5px; }
        pre { background: #ecf0f1; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        .tooltip {
            position: relative;
            display: inline-block;
            border-bottom: 1px dotted black;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 220px;
            background-color: #555;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -110px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        </style>
        <script>
        function sortTable(n) {
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById("scanTable");
            switching = true;
            dir = "asc";
            while (switching) {
            switching = false;
            rows = table.rows;
            for (i = 1; i < (rows.length - 1); i++) {
                shouldSwitch = false;
                x = rows[i].getElementsByTagName("TD")[n];
                y = rows[i + 1].getElementsByTagName("TD")[n];
                if (dir == "asc") {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch= true;
                    break;
                }
                } else if (dir == "desc") {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
                }
            }
            if (shouldSwitch) {
                rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                switching = true;
                switchcount ++;
            } else {
                if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
                }
            }
            }
        }
        </script>
        </head>
        <body>
        <h1>Enhanced Scan Results</h1>
        <div class="summary">
        <strong>Total Scans:</strong> {{ results|length }}<br>
        <strong>Open Ports:</strong> {{ results|selectattr('status', 'equalto', 'open')|list|length }}<br>
        <strong>Closed Ports:</strong> {{ results|selectattr('status', 'equalto', 'closed')|list|length }}<br>
        <strong>Hosts Scanned:</strong> {{ results | map(attribute='target')|unique|list|length }}
        </div>
        <table id="scanTable">
        <thead>
            <tr>
            <th onclick="sortTable(0)">Target</th>
            <th onclick="sortTable(1)">Port</th>
            <th onclick="sortTable(2)">Protocol</th>
            <th onclick="sortTable(3)">Service</th>
            <th>Banner / Info</th>
            <th onclick="sortTable(5)">Status</th>
            <th onclick="sortTable(6)">Timestamp</th>
            <th onclick="sortTable(7)">Timeout Used (s)</th>
            <th onclick="sortTable(8)">Retries</th>
            </tr>
        </thead>
        <tbody>
        {% for result in results %}
            <tr class="{{ 'open' if result.status == 'open' else 'closed' }}">
            <td>{{ result.target }}</td>
            <td>{{ result.port }}</td>
            <td>{{ result.protocol }}</td>
            <td>
                {% if result.service %}
                <div class="tooltip">{{ result.service }}
                    <span class="tooltiptext">Common or banner-identified service</span>
                </div>
                {% else %}
                -
                {% endif %}
            </td>
            <td>
                {% if result.banner %}
                <pre>{{ result.banner }}</pre>
                {% else %}
                -
                {% endif %}
            </td>
            <td>{{ result.status }}</td>
            <td>{{ result.timestamp }}</td>
            <td>{{ "%.2f"|format(result.timeout_used) if result.timeout_used is defined else "-" }}</td>
            <td>{{ result.retries if result.retries is defined else "-" }}</td>
            </tr>
        {% endfor %}
        </tbody>
        </table>
        <p>Click on the table headers to sort the columns.</p>
    </body>
    </html>
    """
    template = Template(html_template)
    rendered_html = template.render(results=results)
    with open(html_report_file, 'w', encoding='utf-8') as f:
        f.write(rendered_html)
    logging.info(f"Enhanced HTML report saved to '{html_report_file}'")

def worker(queue, results, semaphore, pbar, args):
    while not queue.empty():
        target, port, proto, current_timeout = queue.get()
        with semaphore:
            try:
                if proto == 'TCP':
                    result = scan_tcp_port(target, port, current_timeout, args=args)
                elif proto == 'UDP':
                    result = scan_udp_port(target, port, current_timeout, args=args)
                else:
                    result = None
                if result:
                    results.append(result)
                    pbar.update(1)
            except Exception as e:
                logging.error(f"Error processing {target}:{port} - {e}")
        queue.task_done()

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('-c', '--config', type=str, default=TARGETS_CONFIG_FILE, help='Path to targets config JSON file')
    parser.add_argument('-t', '--threads', type=int, default=MAX_THREADS, help='Number of concurrent threads')
    parser.add_argument('--ipv6', action='store_true', help='Enable IPv6 support')
    parser.add_argument('--ports', type=str, help='Comma-separated list or ranges to scan (e.g. 22,80,443 or 1-1000)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--ping-check', action='store_true', help='Skip hosts that fail ping')
    parser.add_argument('--ssl-check', action='store_true', help='Enable SSL/TLS handshake checks on secure ports')
    parser.add_argument('--output-dir', type=str, default='.', help='Directory to store output reports')
    parser.add_argument('--output-prefix', type=str, default='scan_results', help='Prefix for output files')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    LOG_FILE = os.path.join(output_dir, f'{args.output_prefix}.json')
    CSV_FILE = os.path.join(output_dir, f'{args.output_prefix}.csv')
    HTML_REPORT_FILE = os.path.join(output_dir, f'{args.output_prefix}.html')

    targets_conf = load_targets_config(args.config)
    if not targets_conf:
        logging.error("No targets loaded. Exiting.")
        return

    results = []
    scan_tasks = Queue()
    total_tasks = 0

    for target_info in targets_conf:
        target_orig = target_info.get('ip')
        if not target_orig:
            logging.warning("Target entry missing 'ip' field, skipping.")
            continue

        try:
            target_ip = socket.gethostbyname(target_orig)
        except socket.gaierror:
            logging.error(f"Cannot resolve hostname: {target_orig}")
            continue

        if args.ping_check and not ping_host(target_ip):
            logging.warning(f"Skipping {target_orig} ({target_ip}), host unreachable.")
            continue

        target = f'[{target_ip}]' if args.ipv6 else target_ip

        tcp_ports = target_info.get('tcp_ports', list(range(DEFAULT_START_PORT, DEFAULT_END_PORT + 1)))
        udp_ports = target_info.get('udp_ports', [])
        timeout = target_info.get('timeout', initial_timeout)
        target_timeouts[target] = timeout

        if args.ports:
            try:
                specified_ports = set(parse_ports(args.ports))
                tcp_ports = list(set(tcp_ports) & specified_ports)
                udp_ports = list(set(udp_ports) & specified_ports)
            except Exception as e:
                logging.error(f"Error parsing specified ports: {e}")
                continue

        for port in tcp_ports:
            scan_tasks.put((target, port, 'TCP', timeout))
            total_tasks += 1
        for port in udp_ports:
            scan_tasks.put((target, port, 'UDP', timeout))
            total_tasks += 1

    if scan_tasks.empty():
        logging.warning("No scan tasks generated. Exiting.")
        return

    semaphore = Semaphore(args.threads)
    with ThreadPoolExecutor(max_workers=args.threads) as executor, tqdm(total=total_tasks, desc="Scanning") as pbar:
        futures = [executor.submit(worker, scan_tasks, results, semaphore, pbar, args) for _ in range(args.threads)]
        for f in futures:
            f.result()

    with open(LOG_FILE, 'w', encoding='utf-8') as f_json:
        json.dump(results, f_json, indent=2)

    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=['target', 'port', 'protocol', 'service', 'banner', 'status', 'timestamp', 'timeout_used', 'retries'])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    save_html_report(results, HTML_REPORT_FILE)
    logging.info("Scan complete.")
    logging.info(f"Results saved: JSON: {LOG_FILE}, CSV: {CSV_FILE}, HTML: {HTML_REPORT_FILE}")
    logging.info(f"Scan Errors: {scan_errors}")

if __name__ == "__main__":
    import sys

    try:
        main()
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user.")
        sys.exit(0)
