import multithreading
import websocket
import argparse
import sys
import subprocess
import socket
import ssl
import datetime
import os

# Safe monkey-patch for os.get_terminal_size to prevent OSError in subprocesses
_original_get_terminal_size = os.get_terminal_size

def _safe_get_terminal_size(fd=None):
    try:
        if fd is None:
            return _original_get_terminal_size()
        return _original_get_terminal_size(fd)
    except OSError:
        from collections import namedtuple
        TerminalSize = namedtuple('terminal_size', ['columns', 'lines'])
        return TerminalSize(80, 24)

os.get_terminal_size = _safe_get_terminal_size

# Expiry check removed for the web wrapper version

class BugScanner(multithreading.MultiThreadRequest):
    threads: int

    def request_connection_error(self, *args, **kwargs):
        return 1

    def request_read_timeout(self, *args, **kwargs):
        return 1

    def request_timeout(self, *args, **kwargs):
        return 1

    def convert_host_port(self, host, port):
        return host + (f':{port}' if port not in ['80', '443'] else '')

    def get_url(self, host, port, uri=None):
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}' + (f'/{uri}' if uri is not None else '')

    def init(self):
        self._threads = getattr(self, '_threads', 25)
        self._threads = self.threads or self._threads

    def complete(self):
        pass


class DirectScanner(BugScanner):
    method_list = []
    host_list = []
    port_list = []
    isp_redirects = [
        "http://safaricom.zerod.live/?c=77",
        "http://91.220.208.30"
    ]

    def log_info(self, **kwargs):
        for x in ['status_code', 'server']:
            kwargs[x] = kwargs.get(x, '')

        location = kwargs.get('location')

        if location:
            if location.startswith(f"https://{kwargs['host']}"):
                kwargs['status_code'] = f"{kwargs['status_code']:<4}"
            else:
                kwargs['host'] += f" -> {location}"

        messages = []

        for x in ['\033[36m{method:<6}\033[0m', '\033[35m{status_code:<4}\033[0m', '{server:<22}', '\033[94m{port:<4}\033[0m', '\033[92m{host}\033[0m']:
            messages.append(f'{x}')

        super().log('  '.join(messages).format(**kwargs))
        sys.stdout.flush()

    def get_task_list(self):
        for method in self.filter_list(self.method_list):
            for host in self.filter_list(self.host_list):
                for port in self.filter_list(self.port_list):
                    yield {
                        'method': method.upper(),
                        'host': host,
                        'port': port,
                    }

    def init(self):
        super().init()

        self.log_info(method='Method', status_code='Code', server='Server', port='Port', host='Host')
        self.log_info(method='------', status_code='----', server='------', port='----', host='----')

    def task(self, payload):
        method = payload['method']
        host = payload['host']
        port = payload['port']

        try:
            response = self.request(method, self.get_url(host, port), retry=1, timeout=3, allow_redirects=False)
        except Exception as e:
            # Skip errors and continue
            return

        if response is not None:
            status_code = response.status_code
            server = response.headers.get('server', '')
            location = response.headers.get('location', '')

            # Filter out ISP redirect links and status code 302
            if status_code == 302 and location in self.isp_redirects:
                return

            # Log only if there's a valid status code and it's not 302
            if status_code and status_code != 302:
                data = {
                    'method': method,
                    'host': host,
                    'port': port,
                    'status_code': status_code,
                    'server': server,
                    'location': location,
                }

                self.task_success(data)
                self.log_info(**data)


class PingScanner(BugScanner):
    def __init__(self, threads=35):
        super().__init__(threads)
        self.host_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            yield {'host': host}

    def log_info(self, status, host):
        super().log(f'\033[36m{status:<6}\033[0m  \033[92m{host}\033[0m')
        sys.stdout.flush()

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        host = kwargs.get('host', '')

        if status == 'Reachable':
            self.log_info('True', host)

    def init(self):
        super().init()
        self.log_info('Stat', 'Host')
        self.log_info('----', '----')

    def ping_host(self, host):
        try:
            param = '-n' if subprocess.os.name == 'nt' else '-c'
            command = ['ping', param, '1', host]

            response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return response.returncode == 0
        except Exception:
            return False

    def task(self, payload):
        host = payload['host']
        self.log_replace(host)

        if self.ping_host(host):
            response = {
                'host': host,
                'status': 'Reachable'
            }
            self.task_success(host)
            self.log_info_result(**response)


class UdpScanner(BugScanner):
    def __init__(self, threads=30):
        super().__init__(threads)
        self.host_list = []
        self.port_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            for port in self.filter_list(self.port_list):
                yield {
                    'host': host,
                    'port': port
                }

    def log_info(self, status, host, port):
        super().log(f'\033[36m{status:<6}\033[0m  \033[94m{port}\033[0m  \033[92m{host}\033[0m')
        sys.stdout.flush()

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        host = kwargs.get('host', '')
        port = kwargs.get('port', '')

        if status == 'Open':
            self.log_info('True', host, port)

    def init(self):
        super().init()
        self.log_info('Stat', 'Host', 'Port')
        self.log_info('----', '----', '----')

    def scan_udp_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, int(port)))
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False  # UDP might be open but not responding consider it if necessary
        except socket.error:
            return False
        finally:
            sock.close()

    def task(self, payload):
        host = payload['host']
        port = payload['port']
        self.log_replace(f'{host}:{port}')

        if self.scan_udp_port(host, port):
            response = {
                'host': host,
                'port': port,
                'status': 'Open'
            }
            self.task_success(f'{host}:{port}')
            self.log_info_result(**response)


class ProxyScanner(DirectScanner):
    proxy = []

    def log_replace(self, *args):
        super().log_replace(':'.join(self.proxy), *args)

    def request(self, *args, **kwargs):
        proxy = self.get_url(self.proxy[0], self.proxy[1])

        return super().request(*args, proxies={'http': proxy, 'https': proxy}, **kwargs)


class SSLScanner(BugScanner):
    host_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            yield {
                'host': host,
            }

    def log_info(self, status, server_name_indication):
        super().log(f'\033[36m{status:<6}\033[0m  \033[92m{server_name_indication}\033[0m')
        sys.stdout.flush()

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        server_name_indication = kwargs.get('server_name_indication', '')

        if status:
            self.log_info('True', server_name_indication)

    def init(self):
        super().init()
        self.log_info('Status', 'Host')
        self.log_info('------', '----')

    def task(self, payload):
        server_name_indication = payload['host']
        self.log_replace(server_name_indication)
        response = {
            'server_name_indication': server_name_indication,
            'status': False
        }

        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.settimeout(5)
            socket_client.connect((server_name_indication, 443))
            socket_client = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2).wrap_socket(
                socket_client, server_hostname=server_name_indication, do_handshake_on_connect=True
            )
            response['status'] = True
            self.task_success(server_name_indication)
        except Exception:
            pass

        if response['status']:
            self.log_info_result(**response)


class WebSocketScanner(BugScanner):
    host_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            yield {
                'host': host,
            }

    def log_info(self, status, host):
        super().log(f'\033[36m{status:<6}\033[0m  \033[92m{host}\033[0m')
        sys.stdout.flush()

    def log_info_result(self, **kwargs):
        status = kwargs.get('status', '')
        host = kwargs.get('host', '')

        if status in [101, 403, 426, 429, 500, 503]:
            self.log_info('True', host)

    def init(self):
        super().init()
        self.log_info('Stat', 'Host')
        self.log_info('----', '----')

    def task(self, payload):
        host = payload['host']
        url = f"ws://{host}"
        self.log_replace(host)

        response = {
            'host': host,
            'status': None,
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        }

        try:
            ws = websocket.create_connection(url, header=headers)
            ws.send("ping")
            response_msg = ws.recv()
            self.task_success("ping")
            response['status'] = 101
            ws.close()
        except websocket.WebSocketConnectionClosedException as e:
            response['status'] = e.code
        except websocket.WebSocketBadStatusException as e:
            response['status'] = e.status_code
        except websocket.WebSocketException as e:
            response['status'] = None
        except Exception as e:
            response['status'] = None

        if response['status'] in [101, 403, 426, 429, 500, 503]:
            self.task_success(host)
            self.log_info_result(**response)


def get_arguments():
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52))
    parser.add_argument(
        '-f', '--filename',
        help='Filename',
        type=str,
    )
    parser.add_argument(
        '-c', '--cdir',
        help='CIDR (e.g., 192.168.1.0/24)',
        type=str,
    )
    parser.add_argument(
        '-m', '--mode',
        help='mode',
        dest='mode',
        choices=('direct', 'proxy', 'ssl', 'udp', 'ws', 'ping'),
        type=str,
        default='direct',
    )
    parser.add_argument(
        '-M', '--method',
        help='method',
        dest='method_list',
        type=str,
        default='head',
    )
    parser.add_argument(
        '-p', '--port',
        help='port',
        dest='port_list',
        type=str,
        default='80',
    )
    parser.add_argument(
        '-P', '--proxy',
        help='proxy',
        dest='proxy',
        type=str,
        default='',
    )
    parser.add_argument(
        '-o', '--output',
        help='output file name',
        dest='output',
        type=str,
    )
    parser.add_argument(
        '-T', '--threads',
        help='threads',
        dest='threads',
        type=int,
    )
    return parser.parse_args(), parser

def generate_ips_from_cidr(cidr):
    import ipaddress
    ip_list = []
    try:
        network = ipaddress.ip_network(cidr)
        for ip in network.hosts():
            ip_list.append(ip)
    except ValueError as e:
        print("Error:", e)
    return ip_list

def main():
    arguments, parser = get_arguments()

    if not arguments.filename and not arguments.cdir:
        sys.stdout.flush()
        parser.print_help()
        sys.exit()

    method_list = arguments.method_list.split(',')
    if arguments.filename:
        host_list = open(arguments.filename).read().splitlines()
    elif arguments.cdir:
        ip_list = generate_ips_from_cidr(arguments.cdir)
        host_list = [str(ip) for ip in ip_list]

    port_list = arguments.port_list.split(',')
    proxy = arguments.proxy.split(':')

    if arguments.mode == 'direct':
        scanner = DirectScanner()
    elif arguments.mode == 'ssl':
        scanner = SSLScanner()
    elif arguments.mode == 'ping':
        scanner = PingScanner()
    elif arguments.mode == 'ws':
        scanner = WebSocketScanner()
    elif arguments.mode == 'proxy':
        if not proxy or len(proxy) != 2:
            sys.exit('--proxy host:port')
        scanner = ProxyScanner()
        scanner.proxy = proxy
    elif arguments.mode == 'udp':
        scanner = UdpScanner()
    else:
        sys.exit('Not Available!')

    scanner.method_list = method_list
    scanner.host_list = host_list
    scanner.port_list = port_list
    scanner.threads = arguments.threads
    scanner.start()

    if arguments.output:
        with open(arguments.output, 'w+') as file:
            file.write('\n'.join([str(x) for x in scanner.success_list()]) + '\n')

if __name__ == '__main__':
    main()
