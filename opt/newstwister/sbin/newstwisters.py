#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
* possibly multiple requests, to have stored keys locally/statically
* to queue the requests
* take reuests one by one from the queue
* when putting a request into the queue, only put it once, i.e. check for its presence there

* listen:
  * put request into queue
  * trigger twitter request
  * keep the client-side connection
* twitter:
  * while request in queue
    * take first request
    * when data processed, remove the request from queue
    * return the count of messages, and error messages

asynchronously:
  * listen at port, and add to queue, trigger it
  * make a request to twitter and process it
  * put the tweets into a tweet saver (ES/RC)
  * return overall info to the client
'''

import sys, os, time, json, argparse, re
import random
import urllib, select
import oauth2 as oauth
import signal, atexit
import ctypes

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import deferLater
from twisted.internet.protocol import Protocol
from twisted.internet.ssl import ClientContextFactory
from twisted.web import server, resource
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer

from pprint import pformat
from zope.interface import implements
#from twisted.python.log import err

WEB_ADDRESS = '127.0.0.1'
WEB_PORT = 9053
SAVE_URL = 'http://localhost:9200/newstwister/tweets/'

TODEBUG = False
DEBUGPATH = '/tmp/newstwister_search.debug'

def debug_msg(msg):
    if not TODEBUG:
        return

    try:
        fh = open(DEBUGPATH, 'a+')
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
NODE_NAME = 'newstwisters'

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
        parser = argparse.ArgumentParser()
        parser.add_argument('-w', '--web_address', help='web address to listen at')
        parser.add_argument('-p', '--web_port', help='web port to listen at', type=int)
        parser.add_argument('-s', '--save_url', help='url for saving the tweets')

        args = parser.parse_args()
        if args.web_address:
            self.specs['web_address'] = args.web_address
        if args.web_port:
            self.specs['web_port'] = args.web_port
        if args.save_url:
            self.specs['save_url'] = args.save_url

save_specs = SaveSpecs()

class RequestQueue(object):
    def __init__(self):
        self.under_processing = False
        self.request_queue = []
        self.processed_request = None
        self.got_twt_data = []
        self.tweets = []
        self.errors = {}

class StringProducer(object):
    implements(IBodyProducer)
 
    def __init__(self, body):
        self.body = body
        self.length = len(body)
 
    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)
 
    def pauseProducing(self):
        pass
 
    def stopProducing(self):
        pass

class TwtResponseBorders(object):
    def __init__(self, queue_processor, searches):
        self.queue_processor = queue_processor
        self.searches = searches
        self.to_continue = True

    def set_continue(self, value):
        self.to_continue = value

    def cbRequest(self, response):

        debug_msg('Twt response version:' + str(response.version))
        debug_msg('Twt response code:' + str(response.code))
        debug_msg('Twt response phrase:' + str(response.phrase))
        debug_msg('Twt response headers:')
        debug_msg(pformat(list(response.headers.getAllRawHeaders())))

        if '200' != str(response.code):
            self.searches.errors = {
                'code': response.code,
                'phrase': response.phrase
            }
            if str(response.code) in ['420', '429']:
                self.searches.errors['over_limit'] = True
            self.queue_processor.trigger_use_tweets()
            self.queue_processor = None
            self.searches = None
            debug_msg('twitter dislikes the request')
            return False

        finished = Deferred()
        response.deliverBody(TweetProcessor(finished, self, self.queue_processor, self.searches))
        return finished

    def cbShutdown(self, ignored):
        if self.to_continue:
            self.queue_processor.trigger_use_tweets()

        self.queue_processor = None
        self.searches = None
        debug_msg(ignored)
        debug_msg('shutting twt down')

class TweetProcessor(Protocol):
    def __init__(self, finished, borders, queue_processor, searches):
        self.finished = finished
        self.borders = borders
        self.queue_processor = queue_processor
        self.searches = searches
        self.to_continue = False
        self.current = ''

    def connectionMade(self):
        self.to_continue = True
        self.borders.set_continue(False)

    def dataReceived(self, data):

        self.current += data
        if data.endswith('\r\n') and self.current.strip(): # some finished message
            self.searches.got_twt_data.append(self.current)
            self.current = ''

    def connectionLost(self, reason):
        #debug_msg('Finished receiving Twitter search: ' + str(reason.getErrorMessage()))
        self.finished.callback(None)
        if self.current:
            self.searches.got_twt_data.append(self.current)
            self.current = ''

        for one_data_set in self.searches.got_twt_data:
            try:
                data_str = json.loads(one_data_set)
                for one_tweet in data_str['statuses']:
                    self.searches.tweets.append(one_tweet)
            except:
                pass

        self.searches.got_twt_data = []
        self.queue_processor.trigger_use_tweets()
        self.queue_processor = None
        self.searches = None
        self.borders = None

class TwtClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class AuthProcessor(object):
    def get_search_params(self, params):

        search_params = {}

        for one_key in params:
            try:
                search_params[one_key] = params[one_key].decode('utf-8')
            except:
                pass

        return urllib.urlencode(search_params)

    def get_oauth_header(self, param_part):
        global oauth_info_list
        oauth_index = random.randint(0, (len(oauth_info_list) - 1))

        oauth_info = oauth_info_list[oauth_index]

        oauth_consumer = oauth.Consumer(key=oauth_info['consumer_key'], secret=oauth_info['consumer_secret'])
        oauth_token = oauth.Token(key=oauth_info['access_token_key'], secret=oauth_info['access_token_secret'])

        oauth_params = {}
        oauth_params['oauth_version'] = '1.0'
        oauth_params['oauth_nonce'] = oauth.generate_nonce()
        oauth_params['oauth_timestamp'] = int(time.time())

        req_url = 'https://api.twitter.com/1.1/search/tweets.json' + '?' + param_part

        req = oauth.Request(method='GET', parameters=oauth_params, url=req_url)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), oauth_consumer, oauth_token)
        return req.to_header()['Authorization'].encode('utf-8')

    def get_headers(self, param_part):
        conn_headers = {}
        conn_headers['Host'] = ['api.twitter.com']
        conn_headers['Authorization'] = [self.get_oauth_header(param_part)]
        conn_headers['User-Agent'] = ['Newstwister']

        return conn_headers

class QueueProcessor(object):
    def __init__(self, searches):
        self.searches = searches
        self.tweet_count = 0

    def _finish_request(self, request, code=None, message=None):
        try:
            if code:
                request.setResponseCode(code)
        except:
            pass

        try:
            if message:
                request.write(json.dumps({'messsage': message}))
        except:
            pass

        try:
            request.finish()
        except:
            pass

    def got_disconnected(self, err, params):
        try:
            params['call'].cancel()
        except:
            pass

        request_info = params['request_info']

        for rank in self.searches.request_queue:
            one_request = self.searches.request_queue[rank]
            if request_info['user_id'] == one_request['user_id']:
                if request_info['request_id'] == one_request['request_id']:
                    self._finish_request(one_request['request'])
                    self.searches.request_queue.pop(rank)
                    break

    def add_request(self, request_info):
        if self.searches.processed_request:
            if self.searches.processed_request['user_id'] == request_info['user_id']:
                self._finish_request(request, 409, 'already processing a request')
                return False

        rank_replaced = None
        for rank in self.searches.request_queue:
            one_request = self.searches.request_queue[rank]
            if request_info['user_id'] == one_request['user_id']:
                self._finish_request(one_request['request'], 409, 'request replaced by a new request')
                self.searches.request_queue[rank] = request_info
                rank_replaced = rank
                break

        if rank_replaced is not None:
            return True

        self.searches.request_queue.append(request_info)
        return True

    def _process_queue(self):
        if self.searches.under_processing:
            return False
        if not self.searches.request_queue:
            return False
        self.searches.under_processing = True

        self.searches.errors = {}
        self.searches.tweets = []
        self.searches.got_twt_data = []
        self.searches.processed_request = self.searches.request_queue.pop(0)
        self.tweet_count = 0

        auth_sys = AuthProcessor()
        params_urlized = auth_sys.get_search_params(self.searches.processed_request['search_spec'])
        req_headers = auth_sys.get_headers(params_urlized)

        contextFactory = TwtClientContextFactory()
        agent = Agent(reactor, contextFactory)

        d = agent.request(
            'GET',
            'https://api.twitter.com/1.1/search/tweets.json' + '?' + params_urlized,
            Headers(req_headers),
            None)

        borders = TwtResponseBorders(self, self.searches)
        d.addCallback(borders.cbRequest)
        d.addBoth(borders.cbShutdown)

        return True

    def _utilize_tweets(self, params=None):
        # send data stored in self.searches.tweets

        tweet_id = None
        current_tweet = None

        while not tweet_id:
            if not self.searches.tweets:
                break
            current_tweet = self.searches.tweets.pop(0)
            if (not current_tweet) or (type(current_tweet) is not dict):
                continue
            tweet_id = current_tweet.get('id_str')
            if not tweet_id:
                return False

        if (not current_tweet) or (not tweet_id):
            self._finish_pass()
            return

        self.tweet_count += 1

        user_id = self.searches.processed_request['user_id']
        request_id = self.searches.processed_request['request_id']

        save_data = {}
        save_data['request'] = request_id
        save_data['type'] = 'search'
        save_data['endpoint'] = user_id
        save_data['filter'] = self.searches.processed_request['search_spec']
        save_data['tweet'] = current_tweet

        tweet_data = json.dumps(save_data)

        global save_specs

        self.save_url = save_specs.get_specs()['save_url']
        if not self.save_url.endswith('/'):
            self.save_url += '/'

        host = self.save_url[(self.save_url.find(':')+1):]
        host = host[:host.find('/')]

        conn_headers = {}
        conn_headers['Host'] = [host]
        conn_headers['User-Agent'] = ['Newstwister']
        conn_headers['Content-Type'] = ['application/json']
        conn_headers['Accept'] = ['application/json']

        send_url = self.save_url + str(tweet_id)

        contextFactory = ElsClientContextFactory()
        agent = Agent(reactor, contextFactory)

        d_es = agent.request(
            'POST',
            send_url,
            Headers(conn_headers),
            StringProducer(tweet_data))

        borders = ElsResponseBorders(self)
        d_es.addCallback(borders.cbRequest)
        d_es.addBoth(borders.cbShutdown)

    def trigger_use_tweets(self):
        reactor.callLater(0, self._utilize_tweets, {})

    def _finish_pass(self):
        # to call this after all data sent to saver

        try:
            self.searches.processed_request['request'].setResponseCode(200)
        except:
            pass

        return_data = {'count': self.tweet_count}
        if self.searches.errors:
            return_data['errors'] = self.searches.errors

        try:
            self.searches.processed_request['request'].write(json.dumps(return_data))
        except:
            pass

        try:
            self.searches.processed_request['request'].finish()
        except:
            pass

        self.tweet_count = 0
        self.searches.errors = {}
        self.searches.tweets = []
        self.searches.got_twt_data = []
        self.searches.processed_request = None
        self.searches.under_processing = False

        reactor.callLater(0, self.trigger_queue, {})
        return True

    def trigger_queue(self, params=None):
        if self.searches.under_processing:
            return
        if not self.searches.request_queue:
            return

        self._process_queue()

class QueuedResource(resource.Resource):
    isLeaf = True

    def set_processor(self, processor):
        self.processor = processor

    def _extract_data(self, data):
        res = {}

        if (not data) or (type(data) is not dict):
            return (False, 'expecting JSON data')

        params = ['user_id', 'request_id', 'search_spec']
        for key in params:
            if (not key in data) or (not data[key]):
                return (False, 'missing "' + str(key) + '" in data')

        res['user_id'] = str(data['user_id'])
        res['request_id'] = str(data['request_id'])

        has_parts = False
        if type(data['search_spec']) is not dict:
            return (False, 'unsupported "search_spec" data')
        search_spec = data['search_spec']
        parsed_spec = {}

        # search_spec = {
        #    'q': '',
        #    'geocode': '',
        #    'lang': '',
        #    'count': '',
        #    'since_id': '',
        #    'max_id': '',
        #    'result_type': ''
        # }

        has_parts = False
        for part in ['q', 'geocode', 'since_id', 'max_id']:
            if part in search_spec:
                try:
                    parsed_spec[part] = str(search_spec[part])
                except:
                    return (False, 'can not stringify search criteria')
                if parsed_spec[part]:
                    has_parts = True

        if not has_parts:
            return (False, 'no valid search criteria provided')

        for part in ['lang', 'count', 'result_type']:
            if part in search_spec:
                try:
                    parsed_spec[part] = str(search_spec[part])
                except:
                    return (False, 'can not stringify auxiliary criteria')

        res['search_spec'] = parsed_spec

        return (True, res)

    def render_POST(self, request):
        data = None
        try:
            data = request.content.getvalue()
            data = json.loads(data)
        except:
            data = None

        try:
            res = self._extract_data(data)
        except:
            res = (False, 'can not parse request data')

        if not res[0]:
            request.setResponseCode(400)
            return res[1]

        request_info = res[1]
        request_info['request'] = request

        rv = self.processor.add_request(request_info)
        if not rv:
            return False

        call = reactor.callLater(0, self.processor.trigger_queue, {})
        request.notifyFinish().addErrback(self.processor.got_disconnected, {'call': call, 'request_info': request_info})
        return server.NOT_DONE_YET

# Part putting tweets into ES

class ElsClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class ElsResponser(Protocol):
    def __init__(self, finished, borders, queue_processor):
        self.finished = finished
        self.borders = borders
        self.queue_processor = queue_processor
        self.to_continue = False

    def connectionMade(self):
        self.to_continue = True
        self.borders.set_continue(False)

    def dataReceived(self, data):
        debug_msg('got next data from ES: ' + str(data))
        pass

    def connectionLost(self, reason):
        debug_msg('Finished receiving ES response: ' + str(reason.getErrorMessage()))
        self.finished.callback(None)

        if self.to_continue:
            self.queue_processor.trigger_use_tweets()

        self.queue_processor = None

class ElsResponseBorders(object):
    def __init__(self, queue_processor):
        self.queue_processor = queue_processor
        self.to_continue = True

    def set_continue(self, value):
        self.to_continue = value

    def cbRequest(self, response):
        debug_msg('Els response version: ' + str(response.version))
        debug_msg('Els response code: ' + str(response.code))
        debug_msg('Els response phrase: ' + str(response.phrase))
        debug_msg('Els response headers:')
        debug_msg(pformat(list(response.headers.getAllRawHeaders())))

        finished = Deferred()
        response.deliverBody(ElsResponser(finished, self, self.queue_processor))
        return finished

    def cbShutdown(self, ignored):
        if self.to_continue:
            self.queue_processor.trigger_use_tweets()

        self.queue_processor = None
        debug_msg(str(ignored))
        debug_msg('shutting down els connection')
        pass

def process_quit(signal_number, frame):
    try:
        reactor.disconnectAll()
    except:
        pass

    try:
        reactor.stop()
    except:
        pass

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
        searches = RequestQueue()
        processor = QueueProcessor(searches)
        resource = QueuedResource()
        resource.set_processor(processor)
        reactor.listenTCP(specs['web_port'], server.Site(resource), interface=specs['web_address'])
        reactor.run()
