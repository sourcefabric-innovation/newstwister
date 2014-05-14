#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
this is for common simple rest-based requests;
here we shall use simple urllib-based processing,
since these shall be simple, non-frequent queries
'''

import sys, os, time, json, argparse, re
import random
import urllib, urllib2, select
import oauth2 as oauth
import signal, atexit
import ctypes

from pprint import pformat

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

USE_THREADING_SERVER = True
if USE_THREADING_SERVER:
    from SocketServer import ThreadingMixIn as WebMixIn
else:
    from SocketServer import ForkingMixIn as WebMixIn

WEB_ADDRESS = '127.0.0.1'
WEB_PORT = 9052
SAVE_URL_USERS = 'http://localhost:9200/newstwister/users/'

to_debug = False
DEBUG_PATH = '/tmp/newstwister_common.debug'

def debug_msg(msg):
    global to_debug

    if not to_debug:
        return

    try:
        fh = open(DEBUG_PATH, 'a+')
        fh.write(str(msg) + '\n')
        fh.flush()
        fh.close()
    except:
        pass

try:
    import setproctitle
except:
    if not str(sys.platform).lower().startswith('linux'):
        sys.stderr.write('either the setproctitle module has to be available, or the OS has to be Linux')
        sys.exit(1)

PR_SET_NAME = 15
NODE_NAME = 'newstwisterc'

def set_proc_name():
    name_set = False

    try:
        setproctitle.setproctitle(NODE_NAME)
        name_set = True
    except:
        name_set = False

    if name_set:
        return True

    try:
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        buff = ctypes.create_string_buffer(len(NODE_NAME)+1)
        buff.value = NODE_NAME
        libc.prctl(PR_SET_NAME, ctypes.byref(buff), 0, 0, 0)
    except:
        return False

    return True

class RunSpecs():
    def __init__(self):
        self.specs = {
            'web_address': WEB_ADDRESS,
            'web_port': WEB_PORT,
            'save_url': {'user_info': SAVE_URL_USERS}
        }
    def get_specs(self):
        return self.specs

    def use_specs(self):
        global to_debug

        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--web_address', help='web address to listen at')
        parser.add_argument('-p', '--web_port', help='web port to listen at', type=int)
        parser.add_argument('-u', '--save_url_users', help='url for saving the users info')
        parser.add_argument('-d', '--debug', help='whether to write debug info', action='store_true')

        args = parser.parse_args()
        if args.web_address:
            self.specs['web_address'] = args.web_address
        if args.web_port:
            self.specs['web_port'] = args.web_port
        if args.save_url_users:
            self.specs['save_url']['user_info'] = args.save_url_users

        if args.debug:
            to_debug = True

run_specs = RunSpecs()

class TwtInquirer(object):

    def __init__(self, oauth_info):
        self.oauth_info = oauth_info

    def process_request(self, request_type, request_params):
        spec = self.take_request_spec(request_type, request_params)
        if not spec:
            return (False, 'no recognized spec provided')

        effective_url = spec['url']
        if spec['params']:
            connective = '?' if ('?' not in effective_url) else '&'
            effective_url += connective
            effective_url += self.get_urlized(spec['params'])

        oauth_header = self.get_oauth_header(spec['method'], effective_url)

        send_headers = self.get_common_headers()
        send_headers['Authorization'] = oauth_header

        res = self.send_request(spec, send_headers)
        return res

    def take_request_spec(self, request_type, request_params):

        spec = {'method': None, 'url': None, 'params': None}

        if 'user_info' == request_type:
            if type(request_params) is not dict:
                return False

            # https://dev.twitter.com/docs/api/1.1/get/users/show
            spec['method'] = 'GET'
            spec['url'] = 'https://api.twitter.com/1.1/users/show.json?'
            got_user_spec = False
            if ('user_name' in request_params) and request_params['user_name']:
                spec['url'] += 'screen_name=' + str(request_params['user_name'])
                got_user_spec = True
            if (not got_user_spec) and ('user_id' in request_params) and request_params['user_id']:
                spec['url'] += 'user_id=' + str(request_params['user_id'])
                got_user_spec = True
            if not got_user_spec:
                return False

            return spec

        return None

    def get_urlized(self, params):
        if not params:
            return ''

        use_params = {}

        for one_key in params:
            try:
                use_params[one_key] = params[one_key].decode('utf-8')
            except:
                pass

        return urllib.urlencode(use_params)

    def get_oauth_header(self, method='GET', effective_url=None):

        oauth_consumer = oauth.Consumer(key=self.oauth_info['consumer_key'], secret=self.oauth_info['consumer_secret'])
        oauth_token = oauth.Token(key=self.oauth_info['access_token_key'], secret=self.oauth_info['access_token_secret'])

        oauth_params = {}
        oauth_params['oauth_version'] = '1.0'
        oauth_params['oauth_nonce'] = oauth.generate_nonce()
        oauth_params['oauth_timestamp'] = int(time.time())

        req = oauth.Request(method=method, parameters=oauth_params, url=effective_url)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), oauth_consumer, oauth_token)
        return req.to_header()['Authorization'].encode('utf-8')

    def get_common_headers(self):
        conn_headers = {}
        conn_headers['Host'] = 'api.twitter.com'
        conn_headers['User-Agent'] = 'Newstwister'
        conn_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn_headers['Accept'] = 'application/json'

        return conn_headers

    def send_request(self, send_spec, send_headers):
        search_result = None

        send_body = None
        if send_spec['params']:
            send_body = self.get_urlized(send_spec['params'])

        try:
            opener = urllib2.build_opener(urllib2.HTTPSHandler)
            request = urllib2.Request(send_spec['url'], data=send_body, headers=send_headers)
            request.get_method = lambda: send_spec['method']
            response = opener.open(request)
            search_data = response.read()
            response.close()
            search_result = json.loads(search_data)
            if type(search_result) is not dict:
                return (False, 'unknown form of result data from twitter')
        except Exception as exc:
            exc_other = ''
            try:
                exc_other += ' ' + str(exc.message).strip() + ','
            except:
                pass
            try:
                exc_other += ' ' + str(exc.read()).strip() + ','
            except:
                pass
            debug_msg('can not get data from twitter: ' + str(exc) + str(exc_other))
            return (False, 'can not get data from twitter: ' + str(exc) + str(exc_other))

        return (True, search_result)

class ElsDepositor(object):
    def __init__(self, request_type, save_url):
        self.request_type = request_type
        self.save_url = save_url

    def save_result_data(self, data):
        if 'user_info' == self.request_type:
            use_url = self.save_url
            if not use_url.endswith('/'):
                use_url += '/'
            if type(data) is not dict:
                return (False, 'unrecognized user data from twitter')
            if 'id_str' not in data:
                return (False, 'incomplete user data from twitter')
            try:
                use_url += str(data['id_str'])
            except:
                return (False, 'damaged user data from twitter')
            res = self.send_request(use_url, {'user': data})
            return res

        return (False, 'unknown data type for saving')

    def send_request(self, save_url, save_data):
        save_status = None

        save_body = None
        if save_data:
            save_body = json.dumps(save_data)

        save_headers = {
            'Content-Type': 'application/json'
        }
        try:
            req = urllib2.Request(save_url, save_body, save_headers)
            response = urllib2.urlopen(req)
            save_result = response.read()
            save_status = json.loads(save_result)
        except Exception as exc:
            exc_other = ''
            try:
                exc_other += ' ' + str(exc.message).strip() + ','
            except:
                pass
            try:
                exc_other += ' ' + str(exc.read()).strip() + ','
            except:
                pass
            debug_msg('can not save the data: ' + str(exc) + str(exc_other))
            return (False, 'can not save the data: ' + str(exc) + str(exc_other))

        return (True, save_status)

class RequestHandler(BaseHTTPRequestHandler):

    def _write_error(self, msg):
        self.send_response(404)
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def _write_json(self, msg):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(str(msg) + '\n')

    def run_pipe(self, request_type, request_params):
        global oauth_info_list
        global run_specs

        oauth_index = random.randint(0, (len(oauth_info_list) - 1))
        oauth_info = oauth_info_list[oauth_index]

        try:
            specs = run_specs.get_specs()
            save_url = specs['save_url'][request_type]
        except:
            return (False, 'no save-url was provided')

        twtr = TwtInquirer(oauth_info)
        res = twtr.process_request(request_type, request_params)
        if not res:
            return (False, 'error during twitter-related processing')
        if not res[0]:
            return res
        data = res[1]

        elsd = ElsDepositor(request_type, save_url)
        res = elsd.save_result_data(data)
        if not res:
            return (False, 'error during data-saving processing')

        return res

    def do_POST(self):

        content_length = 0
        if self.headers and ('Content-Length' in self.headers):
            try:
                content_length = int(self.headers.getheader('Content-Length'))
            except:
                self._write_error('no length info on request data provided')
                return

        try:
            data_string = self.rfile.read(content_length)
        except:
            self._write_error('can not read request spec data')
            return

        try:
            data_struct = json.loads(data_string.strip())
        except:
            self._write_error('can not parse request spec data: ' + str(data_string.strip()))
            return

        if type(data_struct) is not dict:
            self._write_error('request data not in a form of dict')
            return

        if 'type' not in data_struct:
            self._write_error('"type" not provided in request')
            return
        if 'params' not in data_struct:
            self._write_error('"params" not provided in request')
            return

        res = self.run_pipe(data_struct['type'], data_struct['params'])

        if not res:
            self._write_error('can not process data')
            return
        if not res[0]:
            self._write_error(res[1])
            return

        answer = json.dumps(res[1])
        self._write_json(answer)
        return

class DerivedHTTPServer(WebMixIn, HTTPServer):
    pass

def run_server():
    global run_specs
    specs = run_specs.get_specs()

    server_address = (specs['web_address'], specs['web_port'])
    httpd = DerivedHTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

def process_quit(signal_number, frame):

    cleanup()

def cleanup():
    debug_msg(str(os.getpid()))
    debug_msg('stopping the process')
    os._exit(0)

oauth_info_base = [
    'consumer_key',
    'consumer_secret',
    'access_token_key',
    'access_token_secret'
]
oauth_info_list = []

if __name__ == '__main__':

    if not set_proc_name():
        sys.exit(1)

    run_specs.use_specs()

    signal.signal(signal.SIGINT, process_quit)
    signal.signal(signal.SIGTERM, process_quit)

    atexit.register(cleanup)

    twitter_param_list = []
    while True:
        rfds, wfds, efds = select.select([sys.stdin], [], [], 1)
        if rfds:
            twitter_param_list.append(sys.stdin.readline())
        else:
            break

    is_correct = True
    twitter_params = None

    if not twitter_param_list:
        is_correct = False

    if is_correct:
        try:
            twitter_params = json.loads('\n'.join(twitter_param_list))
            if type(twitter_params) is not dict:
                is_correct = False
            if not twitter_params:
                is_correct = False
        except:
            is_correct = False

    if is_correct:
        try:
            if not 'oauth_info' in twitter_params:
                is_correct = False
            elif type(twitter_params['oauth_info']) not in [list, tuple]:
                is_correct = False
        except:
            is_correct = False

    if is_correct:
        for oauth_set in twitter_params['oauth_info']:
            if not is_correct:
                break
            if type(oauth_set) is not dict:
                is_correct = False
                break
            one_oauth_use = {}
            for part in oauth_info_base:
                if not part in oauth_set:
                    is_correct = False
                    break
                if not oauth_set[part]:
                    is_correct = False
                    break
                try:
                    one_oauth_use[part] = str(oauth_set[part])
                except:
                    is_correct = False
                    break
            if is_correct:
                oauth_info_list.append(one_oauth_use)

    if is_correct:
        run_server()

