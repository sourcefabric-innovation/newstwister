#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
this is for common simpke rest-based requests;
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
WEB_PORT = 9053
SAVE_URL = 'http://localhost:9200/newstwister/users/'

to_debug = False
DEBUG_PATH = '/tmp/newstwister_search.debug'

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
NODE_NAME = 'newstwisteru'

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

class SaveSpecs():
    def __init__(self):
        self.specs = {
            'web_address': WEB_ADDRESS,
            'web_port': WEB_PORT,
            'save_url': SAVE_URL
        }
    def get_specs(self):
        return self.specs

    def set_specs(self, web_address, web_port, save_url):
        self.specs = {
            'web_address': web_address,
            'web_port': web_port,
            'save_url': save_url
        }

    def use_specs(self):
        global to_debug

        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--web_address', help='web address to listen at')
        parser.add_argument('-p', '--web_port', help='web port to listen at', type=int)
        parser.add_argument('-s', '--save_url', help='url for saving the tweets')
        parser.add_argument('-d', '--debug', help='whether to write debug info', action='store_true')

        args = parser.parse_args()
        if args.web_address:
            self.specs['web_address'] = args.web_address
        if args.web_port:
            self.specs['web_port'] = args.web_port
        if args.save_url:
            self.specs['save_url'] = args.save_url

        if args.debug:
            to_debug = True

save_specs = SaveSpecs()

class TwtInquirer(object):

    def __init__(self, oauth_info_list):
        oauth_index = random.randint(0, (len(oauth_info_list) - 1))
        self.oauth_info = oauth_info_list[oauth_index]

    def process_request(self, request_type, request_params):
        spec = self.take_request_spec()
        if not spec:
            return False

        effective_url = spec['url']
        if spec['params']:
            connective = '?' if ('?' not in effective_url) else '&'
            effective_url += connective
            effective_url += self.get_urlized(spec['params'])

        oauth_header = self.get_oauth_header(spec['method'], effective_url)

        send_headers = self.get_common_headers()
        send_headers['Authorization'] = [oauth_header]

        res = send_request(spec, send_headers)
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
                got_user_spec = False
            if (not got_user_spec) and ('user_id' in request_params) and request_params['user_id']:
                spec['url'] += 'user_id=' + str(request_params['user_id'])
                got_user_spec = False
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
        conn_headers['Host'] = ['api.twitter.com']
        conn_headers['User-Agent'] = ['Newstwister']
        conn_headers['Content-Type'] = ['application/x-www-form-urlencoded']
        conn_headers['Accept'] = ['application/json']

        return conn_headers

    def send_request(send_spec, send_headers):
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
                search_result = None
        except Exception as exc:
            search_result = None

        return search_result

class ElsDepositor(object):
    def __init__(self, request_type):
        self.request_type = request_type
        self.save_url = params.get_save_url(request_type)

    def save_result_data(self, data):
        if 'user_info' == self.request_type:
            res = self.send_request(data)
            return res

        return None

    def send_request(save_data):
        save_status = None

        save_body = None
        if save_data:
            send_body = json.dumps(save_data)

        save_headers = {
            'Content-Type': 'application/json'
        }
        try:
            req = urllib2.Request(self.save_url, save_data, save_headers)
            response = urllib2.urlopen(req)
            save_result = response.read()
            save_status = json.loads(save_result)
        except Exception as exc:
            save_status = None

        return save_status

class RequestHandler(BaseHTTPRequestHandler):

    def run_pipe(self, request_type, request_params):
        global oauth_info_list

        twtr = TwtInquirer(oauth_info_list)
        data = twtr.process_request(request_type, request_params)

        elsd = ElsDepositor(params.get_save_url())
        elsd.save_result_data(data)

    def do_POST(self):

        content_length = 0
        if self.headers and ('Content-Length' in self.headers):
            try:
                content_length = int(self.headers.getheader('Content-Length'))
            except:
                content_length = 0

        try:
            self.req_post_data = self.rfile.read(content_length)
        except:
            self.req_post_data = None

        try:
            data_struct = json.loads(data_string.strip())
        except:
            #self._write_error('can not parse request spec data')
            return

        if type(data_struct) is not dict:
            return

        if 'type' not in data_struct:
            return
        if 'params' not in data_struct:
            return

        res = self.run_pipe(data_struct['type'], data_struct['params'])
        return res

class DerivedHTTPServer(WebMixIn, HTTPServer):
    pass

def run_server():
    server_address = (params.get_web_host(), params.get_web_port())
    httpd = DerivedHTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

def process_quit(signal_number, frame):

    cleanup()

def cleanup():
    debug_msg(str(os.getpid()))
    debug_msg('stopping the process')
    os._exit(0)

save_urls = {}

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

    save_specs.use_specs()
    specs = save_specs.get_specs()

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

