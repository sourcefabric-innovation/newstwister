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

import sys, os, time, atexit, signal
import logging, logging.handlers
import resource, urlparse, cgi
import json, argparse
import subprocess
import pwd, grp
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

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
HOME_DIR = '/tmp'

ALLOWED_CLIENTS = ['127.0.0.1']

logger = logging.getLogger()

def setup_logger(log_path):
    global logger

    while logger.handlers:
        logger.removeHandler(logger.handlers[-1])

    formatter = logging.Formatter("%(levelname)s [%(asctime)s]: %(message)s")

    if log_path:
        fh = logging.handlers.WatchedFileHandler(log_path)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    else:
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        logger.addHandler(sh)

    logger.setLevel(logging.INFO)

def is_remote_ip(ip_addr):
    if not ip_addr:
        False
    ip_addr = ip_addr.strip()
    if not ip_addr:
        False

    if ip_addr.startswith('fc00::'):
        return False

    ip_parts = ip_addr.split('.')
    if 4 == len(ip_parts):
        if '10' == ip_parts[0]:
            return False
        if '172' == ip_parts[0]:
            if ip_parts[1].isdigit() and (16 <= int(ip_parts[1])) and (31 >= int(ip_parts[1])):
                return False
        if ('192' == ip_parts[0]) and ('168' == ip_parts[0]):
            return False

    return True

class RunStatus():
    def __init__(self):
        self.status = 0

    def set_status(self, value):
        self.status = value

    def get_status(self):
        return self.status

status = RunStatus()

class ConnectParams():
    def __init__(self):
        self.web_host = WEB_HOST
        self.web_port = WEB_PORT
        self.node_path = NODE_PATH
        self.save_url = SAVE_URL
        self.log_path = None
        self.pid_path = None
        self.allowed = ALLOWED_CLIENTS
        self.home_dir = HOME_DIR
        self.daemonize = False
        self.user_id = None
        self.group_id = None

    def use_specs(self):
        global status
        global logger

        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--web_host', help='web host of this controller, e.g. ' + str(WEB_HOST), default=WEB_HOST)
        parser.add_argument('-p', '--web_port', help='web port of this controller, e.g. ' + str(WEB_PORT), type=int, default=WEB_PORT)

        parser.add_argument('-n', '--node_path', help='node path, e.g. ' + str(NODE_PATH))
        parser.add_argument('-s', '--save_url', help='save url, e.g. ' + str(SAVE_URL))

        parser.add_argument('-l', '--log_path', help='path to log file, e.g. ' + str(LOG_PATH))
        parser.add_argument('-i', '--pid_path', help='path to pid file, e.g. ' + str(PID_PATH))

        parser.add_argument('-a', '--allowed', help='path to file with ip addresses of allowed clients')

        parser.add_argument('-d', '--daemonize', help='daemonize the process', action='store_true')
        parser.add_argument('-u', '--user', help='user of the daemon process')
        parser.add_argument('-g', '--group', help='group of the daemon process')

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

        if args.user:
            try:
                user_info = pwd.getpwnam(args.user)
                self.user_id = int(user_info.pw_uid)
            except:
                logger.error('can not find the daemon user')
                status.set_status(1)
                sys.exit(1)

        if args.group:
            try:
                group_info = grp.getgrnam(args.group)
                self.group_id = int(group_info.gr_gid)
            except:
                logging.error('can not find the daemon group')
                status.set_status(1)
                sys.exit(1)

        if args.daemonize:
            self.daemonize = True
            correct = True
            if not self.log_path:
                logger.error('log path not provided')
                correct = False
            if not self.pid_path:
                logger.error('pid path not provided')
                correct = False
            if not self.user_id:
                logger.error('user name not provided')
                correct = False
            if not self.group_id:
                logger.error('group name not provided')
                correct = False
            if not correct:
                status.set_status(1)
                sys.exit(1)

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

    def get_web_host(self):
        return self.web_host

    def get_web_port(self):
        return self.web_port

    def get_node_path(self):
        return self.node_path

    def get_save_url(self):
        return self.save_url

    def get_log_path(self):
        return self.log_path

    def get_pid_path(self):
        return self.pid_path

    def get_home_dir(self):
        return self.home_dir

    def to_daemonize(self):
        return self.daemonize

    def get_user_id(self):
        return self.user_id

    def get_group_id(self):
        return self.group_id

    def is_allowed(self, ip_address):
        try:
            if str(ip_address) in self.allowed:
                return True
        except:
            return False

        return False

params = ConnectParams()

class NodeHandler():
    def __init__(self):
        self.nodes = {}

    def set_node(self, pid, process):
        pid = str(pid)
        if process is None:
            if pid in self.nodes:
                del(self.nodes[pid])
                return
        self.nodes[pid] = process

    def get_node(self, pid):
        pid = str(pid)
        if pid not in self.nodes:
            return None
        return self.nodes[pid]

nodes = NodeHandler()

class RequestHandler(BaseHTTPRequestHandler):

    def _check_client(self, method):
        global params
        global logger

        remote_ip = str(self.client_address[0])

        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            try:
                forwarded_for = str(forwarded_for).strip()
            except:
                forwarded_for = None

        if forwarded_for:
            got_remote_ips = [x.strip() for x in forwarded_for.split(',') if x]
            cur_ip_rank = len(got_remote_ips) - 1
            while cur_ip_rank >= 0:
                one_rem_ip = got_remote_ips[cur_ip_rank]
                cur_ip_rank -= 1
                if not one_rem_ip:
                    continue
                remote_ip = one_rem_ip
                if is_remote_ip(one_rem_ip):
                    break

        client_allowed = params.is_allowed(remote_ip)
        client_status = 'allowed' if client_allowed else 'forbidden'
        logger.info(str(client_status) + ' request from ' + str(remote_ip) + ' ' + str(method) + ' ' + str(self.path))

        return client_allowed

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
        global logger

        logger.info(msg)
        self.send_response(404)
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def _write_json(self, msg):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def _read_inputs(self):
        self.req_get_params = None
        self.req_post_params = None
        self.req_post_data = None

        parsed_path = urlparse.urlparse(self.path)
        try:
            self.req_get_params = urlparse.parse_qs(parsed_path.query)
        except:
            self.req_get_params = None

        content_length = 0
        if self.headers and ('Content-Length' in self.headers):
            try:
                content_length = int(self.headers.getheader('Content-Length'))
            except:
                content_length = 0

        content_type = ''
        if self.headers and ('Content-Type' in self.headers):
            content_type = self.headers.getheader('Content-Type')

        content_type_value, content_type_params = cgi.parse_header(content_type)
        if content_type_value == 'multipart/form-data':
            try:
                self.req_post_params = cgi.parse_multipart(self.rfile, content_type_params)
            except:
                self.req_post_params = None
        else:
            try:
                self.req_post_data = self.rfile.read(content_length)
            except:
                self.req_post_data = None
            if content_type_value == 'application/x-www-form-urlencoded':
                try:
                    self.req_post_params = urlparse.parse_qs(self.req_post_data)
                except:
                    self.req_post_params = None

    def _get_param(self, method, param, transform):
        value = None

        param_sets = [self.req_post_params, self.req_get_params]
        for one_param_set in param_sets:
            if one_param_set and (param in one_param_set):
                try:
                    value_list = one_param_set[param]
                    if not value_list:
                        value_list = []
                    for one_value in value_list:
                        if not one_value:
                            continue
                        try:
                            one_value = transform(one_value)
                            value = one_value
                            if value:
                                break
                        except:
                            pass
                except:
                    value = None
            if value:
                break

        return value

    def _get_data(self):
        return self.req_post_data

    def do_GET(self):
        global params
        global nodes
        global logger

        if not self._check_client('GET'):
            _write_error('not allowed')
            return

        self._read_inputs()

        if not self.path:
            self.path = ''

        method = None
        main_path = self.path.split('?')[0]
        if main_path.endswith('/_status'):
            method = 'STATUS'

        if not method:
            self._write_error('unknown command')
            return

        pid = self._get_param('GET', 'node', lambda x: int(x))
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
        global logger

        if not self._check_client('POST'):
            _write_error('not allowed')
            return

        self._read_inputs()

        data_string = ''
        data_struct = None

        if not self.path:
            self.path = ''

        command = None
        main_path = self.path.split('?')[0]
        if main_path.endswith('/_start'):
            command = 'START'
        if main_path.endswith('/_stop'):
            command = 'STOP'

        if not command:
            self._write_error('unknown command')
            return

        if 'STOP' == command:
            pid = self._get_param('POST', 'node', lambda x: int(x))
            if not pid:
                self._write_error('pid not provided')
                return

            logger.info('stopping a node: ' + str(pid))

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
                data_string = self.req_post_data
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
                new_process = subprocess.Popen(self.exec_params, bufsize=1, stdin=subprocess.PIPE, close_fds=TRUE, executable=executable_name)
                new_process.stdin.write(json.dump(twitter_params) + '\n')
                new_process.stdin.flush()
                pid = new_process.pid
            except:
                logger.warning('can not write to node')
                self._write_error('error during node creation')
                return

            if not pid:
                self._write_error('can not start node')
                return

            logger.info('started new node: ' + str(pid))

            is_running = self._check_running(pid)
            if is_running:
                nodes.set_node(pid, new_process)

            res = json.dumps({'node': int(pid), 'status': is_running})
            self._write_json(res)

            return

class DerivedHTTPServer(WebMixIn, HTTPServer):
    pass

def daemonize(work_dir, pid_path):
    global status

    UMASK = 022

    if (hasattr(os, 'devnull')):
       REDIRECT_TO = os.devnull
    else:
       REDIRECT_TO = '/dev/null'

    try:
        pid = os.fork()
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        status.set_status(1)
        sys.exit(1)

    if (pid != 0):
        os._exit(0)

    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    try:
        pid = os.fork()
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        status.set_status(1)
        sys.exit(1)

    if (pid != 0):
        os._exit(0)

    try:
        os.chdir(work_dir)
        os.umask(UMASK)
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        status.set_status(1)
        sys.exit(1)

    try:
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(REDIRECT_TO, 'r')
        so = file(REDIRECT_TO, 'a+')
        se = file(REDIRECT_TO, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        status.set_status(1)
        sys.exit(1)

    if pid_path is None:
        logging.warning('no pid file path provided')
    else:
        try:
            fh = open(pid_path, 'w')
            fh.write(str(os.getpid()) + '\n')
            fh.close()
        except Exception:
            logging.error('can not create pid file: ' + str(pid_path))
            status.set_status(1)
            sys.exit(1)

def set_user(user_id, group_id, pid_path):
    global status

    if (user_id is not None) and (str(user_id) != '0'):
        if (pid_path is not None) and os.path.exists(pid_path):
            try:
                os.chown(pid_path, user_id, -1)
            except OSError, e:
                logging.warning('can not set pid file owner: %s [%d]' % (e.strerror, e.errno))

    if group_id is not None:
        try:
            os.setgid(group_id)
        except Exception as e:
            logging.error('can not set group id: %s [%d]' % (e.strerror, e.errno))
            status.set_status(1)
            sys.exit(1)

    if user_id is not None:
        try:
            os.setuid(user_id)
        except Exception as e:
            logging.error('can not set user id: %s [%d]' % (e.strerror, e.errno))
            status.set_status(1)
            sys.exit(1)

def cleanup():
    global logger
    global status

    logger.info('stopping the Twiter-Stream controller')

    pid_path = params.get_pid_path()
    if pid_path is not None:
        try:
            fh = open(pid_path, 'w')
            fh.write('')
            fh.close()
        except Exception:
            logger.warning('can not clean pid file: ' + str(pid_path))

        if os.path.isfile(pid_path):
            try:
                os.unlink(pid_path)
            except Exception:
                pass

    logging.shutdown()
    os._exit(status.get_status())

def exit_handler(signal_number, frame):
    cleanup()

def run_server():
    global params
    global logger
    global status

    logger.info('starting the controller of Twitter-Streaming controller')

    server_address = (params.get_web_host(), params.get_web_port())
    httpd = DerivedHTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    params.use_specs()
    atexit.register(cleanup)

    signal.signal(signal.SIGTERM, exit_handler)
    signal.signal(signal.SIGINT, exit_handler)

    if params.to_daemonize():
        daemonize(params.get_home_dir(), params.get_pid_path())
        set_user(params.get_user_id(), params.get_group_id(), params.get_pid_path())

    setup_logger(params.get_log_path())

    try:
        run_server()
    except Exception as exc:
        logger.error('can not start the Twitter-Streaming controller: ' + str(exc))
        status.set_status(1)
        sys.exit(1)

