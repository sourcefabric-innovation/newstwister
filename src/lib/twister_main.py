#!/usr/bin/env python
#
# Citizen Desk
#

'''
listen on a port
spawn and terminate subprocesses on requests

on any request:
    check if the client is allowed to do requests

on a create POST request:
* i.e. create a node of provided rank

    params as json:
        oauth params
        filter spec

    start a noded
    write all the params (as json) to the noded
        http://stackoverflow.com/questions/4585692/python-nonblocking-subprocess-check-stdout/4585898#4585898
        http://twistedmatrix.com/documents/current/core/howto/process.html

    take PID of the new node, and return it

on a stop POST request:
* i.e. stop a node of provided PID
    try to terminate the node
    try to kill the node

on check GET request:
    p.poll()
    os.kill(pid, 0)

'''

import json
import subprocess
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import sys, os, time, atexit, signal
import logging, logging.handlers
import resource, urlparse, cgi
import pwd, grp

USE_THREADING_SERVER = True
if USE_THREADING_SERVER:
    from SocketServer import ThreadingMixIn as WebMixIn
else:
    from SocketServer import ForkingMixIn as WebMixIn

NODE_NAME = 'twister_node'

WEB_HOST = 'localhost'
WEB_PORT = 9054

NODE_PATH = '/opt/citizendesk/bin/twister_node.py'
SAVE_URL = 'http://localhost:9055/citizendesk/tweets/'

LOG_PATH = '/opt/citizendesk/log/citizendesk/twister_main.log'
PID_PATH = '/opt/citizendesk/run/twister_main.pid'

ALLOWED_CLIENTS = ['127.0.0.1']

logger = logging.getLogger()

def setup_logger(log_path):
    global logger

    while logger.handlers:
        logger.removeHandler(logger.handlers[-1])

    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    #sh = logging.StreamHandler()
    #sh.setFormatter(formatter)
    #logger.addHandler(sh)

    fh = logging.handlers.WatchedFileHandler(log_path)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    logger.setLevel(logging.INFO)

class ConnectParams():
    def __init__(self):
        self.web_host = WEB_HOST
        self.web_port = WEB_PORT
        self.node_path = NODE_PATH
        self.save_url = SAVE_URL
        self.log_path = LOG_PATH
        self.pid_path = PID_PATH
        self.allowed = ALLOWED_CLIENTS

    def use_specs(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-h', '--web_host', help='web host of this controller, e.g. ' + str(WEB_HOST), default=WEB_HOST)
        parser.add_argument('-p', '--web_port', help='web port of this controller, e.g. ' + str(WEB_PORT), type=int, default=WEB_PORT)

        parser.add_argument('-n', '--node_path', help='node path, e.g. ' + str(NODE_PATH))
        parser.add_argument('-s', '--save_url', help='save url, e.g. ' + str(SAVE_URL))

        parser.add_argument('-l', '--log_path', help='path to log file, e.g. ' + str(LOG_PATH))
        parser.add_argument('-i', '--pid_path', help='path to pid file, e.g. ' + str(PID_PATH))

        parser.add_argument('-a', '--allowed', help='path to file with ip addresses of allowed clients')

        args = parser.parse_args()
        if args.web_host:
            self.web_host = args.web_host
        if args.web_port:
            self.web_port = int(args.web_port)
        if args.node_path:
            self.node_path = args.node_path
        if args.save_url:
            self.save_url = args.save_url

        if args.log_path:
            self.log_path = args.log_path
        if args.pid_path:
            self.pid_path = args.pid_path
        setup_logger(self.log_path)

        if args.allowed:
            try:
                self.allowed = []
                fh = open(args.allowed, 'r')
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('#'):
                        continue
                    self.allowed.append(line)
                fh.close()
            except:
                self.allowed = ALLOWED_CLIENTS

    def get_web_host():
        return self.web_host

    def get_web_port():
        return self.web_port

    def get_node_path():
        return self.node_path

    def get_save_url():
        return self.save_url

    def is_allowed(ip_address):
        if str(ip_address) in self.allowed:
            return True
        return False

params = ConnectParams()

class NodeHandler():
    def __init__(self):
        self.nodes = {}

    def set_node(pid, process):
        pid = str(pid)
        if process is None:
            if pid in self.nodes:
                del(self.nodes[pid])
                return
        self.nodes[pid] = process

    def get_node(pid):
        pid = str(pid)
        if pid not in self.nodes:
            return None
        return self.nodes[pid]

nodes = NodeHandler()

class RequestHandler(BaseHTTPRequestHandler):

    def _check_client(self):
        global params

        client_ip = str(self.client_address[0])
        return params(client_ip)

        return False

    def _check_running(self, pid):
        try:
            pid = int(pid)
        except:
            return False

        try:
            os.kill(int(pid), 0)
        except:
            return False

        return True

    def _write_error(self, msg):
        self.send_response(404)
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def _write_json(self, msg):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def _get_param(self, param, transform):
        value = None

        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=environment)
        for field in form.keys():
            if field == param:
                try:
                    value = form[field]
                    value = transform(value)
                except:
                    value = None
                    continue
                if value:
                    break

        return value

    def do_GET(self):
        global params
        global nodes

        if not self._check_client():
            _write_error('not allowed')
            return

        if not self.path:
            self.path = ''

        method = None
        if self.path.endswith('/_status'):
            method = 'STATUS'

        if not method:
            self._write_error('unknown method')
            return

        pid = self._get_param('pid', lambda x: int(x))
        if not pid:
            self._write_error('pid not provided')
            return

        is_running = self._check_running(pid)
        if not is_running:
            old_process = nodes.get_node(pid)
            if old_process:
                nodes.set_node(pid, None)

        res = json.dumps({'node': int(pid), 'status': is_running})
        self._write_json(res)

        return

    def do_POST(self):
        global params
        global nodes

        if not self._check_client():
            _write_error('not allowed')
            return

        data_string = ''
        data_struct = None

        if not self.path:
            self.path = ''

        command = None
        if self.path.endswith('/_start'):
            command = 'START'
        if self.path.endswith('/_stop'):
            command = 'STOP'

        if not command:
            self._write_error('unknown command')
            return

        parsed_path = urlparse.urlparse(self.path)
        parsed_params = urlparse.parse_qs(parsed_path.query)

        if 'STOP' == command:
            pid = self._get_param('pid', lambda x: int(x))
            if not pid:
                self._write_error('pid not provided')
                return

            for ind in range(4):
                try:
                    os.kill(int(pid), signal.SIGTERM)
                    time.sleep(0.05)
                except:
                    break

            try:
                os.kill(int(pid), signal.SIGKILL)
            except:
                pass

            old_process = nodes.get_node(pid)
            if old_process:
                try:
                    old_process.terminate()
                except:
                    pass
                try:
                    old_process.kill()
                except:
                    pass
                try:
                    old_process.wait()
                except:
                    pass
                nodes.set_node(pid, None)

            is_running = self._check_running(pid)

            res = json.dumps({'node': int(pid), 'status': is_running})
            self._write_json(res)

            return

        if 'START' == command:

            try:
                data_string = self.rfile.read(int(self.headers['Content-Length']))
            except:
                self._write_error('no spec data')
                return

            try:
                data_struct = json.loads(data_string.strip())
            except:
                self._write_error('can not parse spec data')
                return

            self.node_path = params.get_node_path()
            self.exec_params = [NODE_NAME, self.node_path, '-s', params.get_save_url()]
            twitter_params = data_struct

            pid = None
            executable_name = 'python' + str(sys.version_info.major) + '.' +str(sys.version_info.minor)

            try:
                p = subprocess.Popen(self.exec_params, bufsize=1, stdin=subprocess.PIPE, close_fds=TRUE, executable=executable_name)
                p.stdin.write(json.dump(twitter_params) + '\n')
                p.stdin.flush()
                pid = p.pid
            except:
                logging.warning('can not write to node')
                self._write_error('error during node creation')
                return

            if not pid:
                self._write_error('can not start node')
                return

            is_running = self._check_running(pid)
            if is_running:
                nodes.set_node(pid, p)

            res = json.dumps({'node': int(pid), 'status': is_running})
            self._write_json(res)

            return

class DerivedHTTPServer(WebMixIn, HTTPServer):
    pass

def run_server(ip_address, port):
    global params
    global logger

    params.use_specs()

    logger.info('starting the controller of Twitter-Streaming nodes web server')

    server_address = (params.get_web_host(), params.get_web_port())
    httpd = DerivedHTTPServer(server_address, RequestHandler)
    httpd.serve_forever()


