import asyncio
import json
import csv
import random
import time
import argparse
import logging
import platform
import subprocess
from jinja2 import Template

# --- Config ---
DEFAULT_MAX_CONCURRENT = 100
DEFAULT_BASE_DELAY = 0.01
TARGETS_CONFIG_FILE = 'targets_config.json'
LOG_FILE = 'scan_results.json'
CSV_FILE = 'scan_results.csv'
HTML_REPORT_FILE = 'scan_results.html'

# Service fingerprint database
SERVICE_DB = {
    'ssh': ['ssh', 'sshd'],
    'http': ['http', 'apache', 'nginx'],
    'ftp': ['ftp'],
    'smtp': ['smtp'],
    'pop3': ['pop3'],
    'imap': ['imap'],
    'mysql': ['mysql'],
    'postgres': ['postgresql'],
    'redis': ['redis']
}

# --- Error counters ---
scan_errors = {
    'timeouts': 0,
    'failed_connections': 0,
    'other_errors': 0
}

# --- Load targets ---
def load_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data.get('targets', [])
    except Exception as e:
        print(f"Error loading targets: {e}")
        return []

def identify_service(banner):
    banner_lower = (banner or '').lower()
    for service, keywords in SERVICE_DB.items():
        for kw in keywords:
            if kw in banner_lower:
                return service
    return 'unknown'

def simple_os_guess(banner):
    banner_lower = (banner or '').lower()
    if 'ubuntu' in banner_lower:
        return 'Ubuntu/Linux'
    elif 'windows' in banner_lower:
        return 'Windows'
    elif 'mac' in banner_lower:
        return 'macOS'
    elif 'freebsd' in banner_lower:
        return 'FreeBSD'
    return 'Unknown'

async def check_ssl(target, port):
    """Attempt SSL handshake to detect secure service."""
    import ssl
    try:
        reader, writer = await asyncio.open_connection(target, port, ssl=None)
        sslcontext = ssl.create_default_context()
        ssl_reader, ssl_writer = await asyncio.start_tls(reader, writer, sslcontext, server_hostname=target)
        ssl_writer.close()
        await ssl_writer.wait_closed()
        return True
    except:
        return False

async def scan_tcp(target, port, timeout, retries=2, ssl_check=False):
    """Scan TCP port with banner, SSL, OS guess."""
    for attempt in range(retries):
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = ''
            try:
                # Send a simple request if HTTP
                if port in [80, 8080, 443]:
                    writer.write(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % target.encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.read(1024), timeout=1)
                    banner = resp.decode(errors='ignore')
                else:
                    # Try to read banner
                    # (simulate banner for demo)
                    banner = 'Sample banner for port %s' % port
            except:
                pass
            service = identify_service(banner)
            os_guess = simple_os_guess(banner)
            ssl = False
            if ssl_check and port in [443, 465, 993, 995]:
                ssl = await check_ssl(target, port)
                if ssl:
                    service = f"SSL/{service}"
            writer.close()
            await writer.wait_closed()
            # Success: lower timeout
            return {
                'target': target,
                'port': port,
                'protocol': 'TCP',
                'service': service,
                'banner': banner,
                'os_guess': os_guess,
                'status': 'open',
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'timeout': timeout,
                'retries': attempt + 1
            }
        except asyncio.TimeoutError:
            scan_errors['timeouts'] += 1
            # Increase timeout for next attempt
            timeout = min(max_timeout, timeout * timeout_increase_factor)
        except Exception as e:
            scan_errors['other_errors'] += 1
            return {
                'target': target,
                'port': port,
                'protocol': 'TCP',
                'status': 'error',
                'error': str(e),
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'timeout': timeout,
                'retries': attempt + 1
            }
    # After retries: closed
    return {
        'target': target,
        'port': port,
        'protocol': 'TCP',
        'status': 'closed',
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'timeout': timeout,
        'retries': retries
    }

async def scan_udp(target, port, timeout, retries=2):
    """Scan UDP port with basic response."""
    for attempt in range(retries):
        try:
            transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(target, port))
            # Send a dummy packet
            transport.sendto(b'')
            await asyncio.sleep(timeout)
            transport.close()
            return {
                'target': target,
                'port': port,
                'protocol': 'UDP',
                'status': 'open',
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'timeout': timeout,
                'retries': attempt + 1
            }
        except:
            # Timeout or error
            if attempt < retries - 1:
                # Increase timeout
                timeout = min(max_timeout, timeout * timeout_increase_factor)
            else:
                return {
                    'target': target,
                    'port': port,
                    'protocol': 'UDP',
                    'status': 'closed',
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'timeout': timeout,
                    'retries': retries
                }

def save_html(results, filename):
    """Generate a detailed HTML report."""
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Results</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background:#f4f4f4; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #999; padding: 8px; text-align: left; }
            th { background-color: #333; color: #fff; cursor: pointer; }
            tr:nth-child(even) { background: #eee; }
            .open { background-color: #d4edda; }
            .closed { background-color: #f8d7da; }
        </style>
    </head>
    <body>
    <h2>Scan Results</h2>
    <table id="resultTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Target</th>
                <th onclick="sortTable(1)">Port</th>
                <th onclick="sortTable(2)">Protocol</th>
                <th onclick="sortTable(3)">Service</th>
                <th>Banner</th>
                <th onclick="sortTable(5)">OS Guess</th>
                <th onclick="sortTable(6)">Status</th>
                <th onclick="sortTable(7)">Timestamp</th>
                <th onclick="sortTable(8)">Timeout (s)</th>
                <th onclick="sortTable(9)">Retries</th>
            </tr>
        </thead>
        <tbody>
        {% for r in results %}
            <tr class="{{ r.status }}">
                <td>{{ r.target }}</td>
                <td>{{ r.port }}</td>
                <td>{{ r.protocol }}</td>
                <td>{{ r.service or '-' }}</td>
                <td><pre>{{ r.banner or '-' }}</pre></td>
                <td>{{ r.os_guess or '-' }}</td>
                <td>{{ r.status }}</td>
                <td>{{ r.timestamp }}</td>
                <td>{{ "%.2f"|format(r.timeout) }}</td>
                <td>{{ r.retries }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    <script>
    function sortTable(n) {
        var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
        table = document.getElementById("resultTable");
        switching = true;
        dir = "asc"; 
        while (switching) {
            switching = false;
            rows = table.rows;
            for (i=1; i<rows.length-1; i++) {
                shouldSwitch = false;
                x = rows[i].getElementsByTagName("TD")[n];
                y = rows[i+1].getElementsByTagName("TD")[n];
                if (dir=="asc") {
                    if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                        shouldSwitch=true; break;
                    }
                } else {
                    if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                        shouldSwitch=true; break;
                    }
                }
            }
            if (shouldSwitch) {
                rows[i].parentNode.insertBefore(rows[i+1], rows[i]);
                switching=true; switchcount++;
            } else {
                if (switchcount==0 && dir=="asc") {
                    dir="desc"; switching=true;
                }
            }
        }
    }
    </script>
    </body>
    </html>
    """
    t = Template(template_str)
    html = t.render(results=results)
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default=TARGETS_CONFIG_FILE)
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_MAX_CONCURRENT)
    parser.add_argument('--ssl', action='store_true', help='Check SSL support')
    args = parser.parse_args()

    targets = load_targets(args.config)
    if not targets:
        print("No targets loaded.")
        return

    tasks = []
    results = []

    for target_info in targets:
        target_ip = target_info['ip']
        tcp_ports = target_info.get('tcp_ports', list(range(1,1025)))
        udp_ports = target_info.get('udp_ports', [])
        timeout = target_info.get('timeout', initial_timeout)
        for port in tcp_ports:
            tasks.append(('TCP', target_ip, port, timeout))
        for port in udp_ports:
            tasks.append(('UDP', target_ip, port, timeout))

    sem = asyncio.Semaphore(args.threads)
    pbar = tqdm(total=len(tasks))

    async def worker(task):
        async with sem:
            proto, target, port, timeout = task
            if proto=='TCP':
                res = await scan_tcp(target, port, timeout, ssl_check=args.ssl)
            else:
                res = await scan_udp(target, port, timeout)
            results.append(res)
            pbar.update(1)

    await asyncio.gather(*(worker(t) for t in tasks))
    pbar.close()

    # Save results
    with open(LOG_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    # Save CSV
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['target','port','protocol','service','banner','os_guess','status','timestamp','timeout','retries'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    # Save HTML report
    save_html(results, HTML_REPORT_FILE)

async def scan_tcp(target, port, timeout, ssl_check=False):
    """Perform TCP scan with banner, SSL, OS detection."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        banner = ''
        if port in [80, 8080, 443]:
            # Send HTTP HEAD
            writer.write(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % target.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=1)
            banner = resp.decode(errors='ignore')
        else:
            # Simulate banner for demo
            banner = 'Sample banner'
        service = identify_service(banner)
        os_guess = simple_os_guess(banner)
        ssl_supported = False
        if ssl_check and port in [443, 465, 993, 995]:
            ssl_supported = await check_ssl(target, port)
            if ssl_supported:
                service = f"SSL/{service}"
        writer.close()
        await writer.wait_closed()
        return {
            'target': target,
            'port': port,
            'protocol': 'TCP',
            'service': service,
            'banner': banner,
            'os_guess': os_guess,
            'status': 'open',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'timeout': timeout,
            'retries': 1
        }
    except Exception as e:
        return {
            'target': target,
            'port': port,
            'protocol': 'TCP',
            'status': 'closed',
            'error': str(e),
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'timeout': timeout,
            'retries': 1
        }

async def check_ssl(target, port):
    """Attempt SSL handshake detection."""
    try:
        reader, writer = await asyncio.open_connection(target, port, ssl=None)
        sslcontext = ssl.create_default_context()
        ssl_reader, ssl_writer = await asyncio.start_tls(reader, writer, sslcontext, server_hostname=target)
        ssl_writer.close()
        await ssl_writer.wait_closed()
        return True
    except:
        return False

async def scan_udp(target, port, timeout):
    """UDP scan with a dummy payload."""
    try:
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(target, port))
        transport.sendto(b'')
        await asyncio.sleep(timeout)
        transport.close()
        return {
            'target': target,
            'port': port,
            'protocol': 'UDP',
            'status': 'open',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'timeout': timeout,
            'retries': 1
        }
    except:
        return {
            'target': target,
            'port': port,
            'protocol': 'UDP',
            'status': 'closed',
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'timeout': timeout,
            'retries': 1
        }

def parse_dns_response(data):
    """Parse DNS response for service detection."""
    if data and len(data) > 12:
        response_code = data[3] & 0x0F
        if response_code == 0:
            return "DNS"
    return "Unknown"

def save_html(results, filename):
    """Generate a detailed, styled HTML report."""
    template_str = """<!DOCTYPE html>
<html>
<head>
<title>Scan Results</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background:#f4f4f4; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #999; padding: 8px; text-align: left; }
th { background-color: #333; color: #fff; cursor: pointer; }
tr:nth-child(even) { background: #eee; }
.open { background-color: #d4edda; }
.closed { background-color: #f8d7da; }
</style>
<script>
function sortTable(n) {
    var table = document.getElementById("resultTable");
    var switching = true; var dir = "asc"; var switchcount=0;
    while (switching) {
        switching = false;
        var rows = table.rows;
        for (var i=1;i<(rows.length-1);i++) {
            var shouldSwitch=false;
            var x=rows[i].getElementsByTagName("TD")[n];
            var y=rows[i+1].getElementsByTagName("TD")[n];
            if (dir=="asc") {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch=true; break;
                }
            } else {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch=true; break;
                }
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i+1], rows[i]);
            switching=true; switchcount++;
        } else {
            if (switchcount==0 && dir=="asc") {
                dir="desc"; switching=true;
            }
        }
    }
}
</script>
</head>
<body>
<h2>Scan Results</h2>
<table id="resultTable">
<thead>
<tr>
<th onclick="sortTable(0)">Target</th>
<th onclick="sortTable(1)">Port</th>
<th onclick="sortTable(2)">Protocol</th>
<th onclick="sortTable(3)">Service</th>
<th>Banner</th>
<th onclick="sortTable(5)">OS Guess</th>
<th onclick="sortTable(6)">Status</th>
<th onclick="sortTable(7)">Timestamp</th>
<th onclick="sortTable(8)">Timeout (s)</th>
<th onclick="sortTable(9)">Retries</th>
</tr>
</thead>
<tbody>
{% for r in results %}
<tr class="{{ r.status }}">
<td>{{ r.target }}</td>
<td>{{ r.port }}</td>
<td>{{ r.protocol }}</td>
<td>{{ r.service or '-' }}</td>
<td><pre>{{ r.banner or '-' }}</pre></td>
<td>{{ r.os_guess or '-' }}</td>
<td>{{ r.status }}</td>
<td>{{ r.timestamp }}</td>
<td>{{ "%.2f"|format(r.timeout) }}</td>
<td>{{ r.retries }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>"""
    t=Template(template_str)
    html=t.render(results=results)
    with open(filename,'w',encoding='utf-8') as f:
        f.write(html)

# Main execution
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', default='targets_config.json')
    parser.add_argument('-t','--threads', type=int, default=100)
    parser.add_argument('--ssl', action='store_true', help='Check SSL support')
    args=parser.parse_args()

    targets=load_targets(args.config)
    if not targets:
        print("No targets loaded.")
        return

    tasks=[]
    for t in targets:
        target_ip = t['ip']
        tcp_ports = t.get('tcp_ports', list(range(1,1025)))
        udp_ports = t.get('udp_ports', [])
        timeout = t.get('timeout', initial_timeout)
        for p in tcp_ports:
            tasks.append(('TCP', target_ip, p, timeout))
        for p in udp_ports:
            tasks.append(('UDP', target_ip, p, timeout))
    sem=asyncio.Semaphore(args.threads)
    pbar=tqdm(total=len(tasks))
    results=[]
    async def worker(task):
        async with sem:
            proto, target, port, timeout=task
            if proto=='TCP':
                res=await scan_tcp(target, port, timeout, ssl_check=args.ssl)
            else:
                res=await scan_udp(target, port, timeout)
            results.append(res)
            pbar.update(1)
    await asyncio.gather(*(worker(t) for t in tasks))
    pbar.close()

    # Save results
    with open('results.json','w') as f:
        json.dump(results,f,indent=2)
    # Save CSV
    with open('results.csv','w',newline='') as f:
        writer=csv.DictWriter(f, fieldnames=['target','port','protocol','service','banner','os_guess','status','timestamp','timeout','retries'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # Save HTML report
    save_html(results, HTML_REPORT_FILE)

# Run
if __name__=='__main__':
    import asyncio
    asyncio.run(main())
