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

SAVE_URL = 'http://localhost:9200/newstwister/tweets/'

'''
# initial setting

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
            'save_url': SAVE_URL
        }
    def get_specs(self):
        return self.specs

    def set_specs(self, save_url):
        self.specs = {
            'save_url': save_url
        }

    def use_specs(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', '--save_url', help='url for saving the tweets')

        args = parser.parse_args()
        if args.save_url:
            self.specs['save_url'] = args.save_url

save_specs = SaveSpecs()

'''

TODEBUG = False
DEBUGPATH = '/tmp/newstwister_node.debug'

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

class RequestQueue(object):
    def __init__(self):
        self.under_processing = False
        self.request_queue = []
        self.processed_request = None
        self.got_twt_data = []
        self.tweets = []

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
        #self.buffers = []
        self.current = ''

    def connectionMade(self):
        self.to_continue = True
        self.borders.set_continue(False)

    def dataReceived(self, data):

        self.current += data
        if data.endswith('\r\n') and self.current.strip(): # some finished message
            #self.buffers.append(self.current)
            self.searches.got_twt_data.append(self.current)
            self.current = ''

            #message = json.loads(self.buffer)
            ## putting the tweet into elastic search
            #tws = TweetSaver()
            #tws.save_tweet(message)

    def connectionLost(self, reason):
        #debug_msg('Finished receiving Twitter stream: ' + str(reason.getErrorMessage()))
        self.finished.callback(None)
        if self.current:
            #self.buffers.append(self.current)
            self.searches.got_twt_data.append(self.current)
            self.current = ''

        #self.searches.tweets = []
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
        global oauth_info

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
        #self.under_processing = False
        #self.request_queue = []
        #self.processed_request = None
        #self.got_twt_data = []
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

        #self.searches.processed_request['twitter'] = d

        return True

    def _utilize_tweets(self, params=None):
        #self.searches.processed_request['twitter'] = None

        # send data stored in self.searches.tweets
        if not self.searches.tweets:
            self._finish_pass()
            return

        self.tweet_count += 1
        current_tweet = self.searches.tweets.pop(0)
        tweet_id = current_tweet['id_str']

        #tweet_data = None
        tweet_data = json.dumps(current_tweet)

        self.save_url = SAVE_URL
        send_url = self.save_url + str(tweet_id)
        conn_headers = {}

        '''
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

        tweet_id = tweet.get('id_str')
        if not tweet_id:
            return False
        save_data = {}
        save_data['endpoint'] = endpoint
        save_data['filter'] = stream_filter
        save_data['tweet'] = tweet

        tweet_data = json.dumps(save_data)

        send_url = self.save_url + str(tweet_id)
        '''

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

        try:
            self.searches.processed_request['request'].write(json.dumps({'count': self.tweet_count}))
        except:
            pass

        try:
            self.searches.processed_request['request'].finish()
        except:
            pass

        self.tweet_count = 0
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

    def _parse_data(self, data):
        res = {}

        if (not data) or (type(data) is not dict):
            return (False, 'expecting JSON data')

        params = ['user_id', 'request_id', 'search_spec']
        for key in params:
            if (not key in data) or (not data[key]):
                return (False, 'missing "' + str(key) + '" in data')

        res['user_id'] = str(data['user_id'])
        res['request_id'] = str(data['request_id'])

        parsed = {}
        has_parts = False
        if type(data['search_spec']) is not dict:
            return (False, 'unsupported "search_spec" data')
        search_spec = data['search_spec']

        # having_any: boolean, true for OR, false for AND (default)
        # contains: keywords, #hashtags, @screen_names
        # since/until: yyyy-mm-dd
        # radius_unit: "km", "mi"
        # result_type: "mixed", "recent", "popular"
        #
        # search_spec = {
        #    'query': {'having_any': None, 'contains': [], 'from': None, 'to': None, 'without': None, 'since': None, 'until': None},
        #    'geo': {'latitude': None, 'longitude': None, 'radius': None, 'radius_unit': None},
        #    'lang': None,
        #    'count': None,
        #    'since_id': None,
        #    'max_id': None,
        #    'result_type': None
        # }

        if ('query' not in search_spec) or (type(search_spec['query']) is not dict):
            return (False, 'query dictionary should be provided in "search_spec" data')
        query_part = search_spec['query']

        query_connective = ' '
        if ('having_any' in query_part) and query_part['having_any']:
            query_connective = ' OR '

        query_terms = []

        if ('contains' in query_part) and (type(query_part['contains']) is list) and query_part['contains']:
            for one_term in query_part['contains']:
                one_term = one_term.strip()
                if not one_term:
                    continue
                if one_term.lower() in ['and', 'or']:
                    return (False, 'boolean operators shall not be term parameters')
                if ' ' in one_term:
                    if not one_term.startswith('"'):
                        one_term = '"' + one_term
                    if not one_term.endswith('"'):
                        one_term = one_term + '"'
                query_terms.append(one_term)

        for spec_key in ['from', 'to']:
            if (spec_key in query_part) and query_part[spec_key]:
                screen_name = query_part[spec_key]
                if screen_name.startswith('@'):
                    screen_name = screen_name[1:]
                    if screen_name:
                        query_terms.append(screen_name)

        if ('without' in query_part) and query_part['without']:
            query_terms.append('-' + query_part['without'])

        for spec_key in ['since', 'until']:
            if (spec_key in query_part) and query_part[spec_key]:
                date_str = query_part[spec_key]
                if not re.match('^[\d]{4}-[\d]{2}-[\d]{2}$', date_str):
                    return (False, 'date specifiers shall be in the form "YYYY-MM-DD"')
                query_terms.append(spec_key + ':' + query_part[spec_key])

        parsed['q'] = query_connective.join(query_terms)
        if len(query_terms):
            has_parts = True

        if ('geocode' in search_spec) and (type(search_spec['geocode']) is dict):
            has_geo = True
            geo_part = search_spec['geocode']
            for geo_spec in ['latitude', 'longitude', 'radius', 'radius_unit']:
                if geo_spec not in geo_part:
                    has_geo = False
                    continue
                if not geo_part[geo_spec]:
                    has_geo = False
                    continue
            if has_geo:
                if geo_spec['radius_unit'] not in ['km', 'mi']:
                    has_geo = False
                    return (False, 'radius unit geo specifier shall be either "km" or "mi"')
            if has_geo:
                use_geocode = str(geo_part['latitude']) + ',' + str(geo_part['longitude']) + ','
                use_geocode += str(geo_part['radius']) + str(geo_part['radius_unit'])
                parsed['geocode'] = use_geocode
                has_parts = True

        for one_id_part in ['since_id', 'max_id']:
            if (one_id_part in search_spec) and search_spec[one_id_part]:
                if not str(search_spec[one_id_part]).isdigit():
                    return (False, '"' + str(one_id_part) + '" shall be a digital string')
                parsed[one_id_part] = str(search_spec[one_id_part])
                has_parts = True

        if not has_parts:
            return (False, 'no applicable search specification provided')

        if ('count' in search_spec) and search_spec['count']:
            if not str(search_spec['count']).isdigit():
                return (False, '"count" shall be a digital string')
            parsed['count'] = str(search_spec['count'])

        if ('lang' in search_spec) and search_spec['lang']:
            if 2 is not len(search_spec['lang']):
                return (False, '"lang" shall be a (2-letter) language ISO 639-1 specification')
            parsed['lang'] = str(search_spec['lang'])

        parsed['result_type'] = 'mixed'
        if ('result_type' in search_spec) and search_spec['result_type']:
            if search_spec['result_type'] not in ['mixed', 'recent', 'popular']:
                return (False, '"result_type" shall be one of "mixed", "recent", "popular"')
            parsed['result_type'] = search_spec['result_type']

        res['search_spec'] = parsed

        return (True, res)

    def render_POST(self, request):
        data = None
        try:
            data = request.content.getvalue()
            data = json.loads(data)
        except:
            data = None

        try:
            res = self._parse_data(data)
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

'''
# General script passage

def signal_handler(signal_number, frame):
    global d

    d.cancel()
    reactor.disconnectAll()
    process_quit(signal_number, frame)

def process_quit(signal_number, frame):
    cleanup()

def cleanup():
    debug_msg(str(os.getpid()))
    debug_msg('stopping the process')
    os._exit(0)

endpoint = {
    'endpoint_id': None
}
oauth_info = {
    'consumer_key': None,
    'consumer_secret': None,
    'access_token_key': None,
    'access_token_secret': None
}
stream_filter = {}
stream_filter_basic = [
    'follow',
    'track',
    'locations'
]
stream_filter_other = [
    'filter_level',
    'language'
]

if __name__ == '__main__':

    if not set_proc_name():
        sys.exit(1)

    save_specs.use_specs()

    signal.signal(signal.SIGINT, signal_handler)
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
            elif type(twitter_params['oauth_info']) is not dict:
                is_correct = False
            #else:
            #    oauth_info = twitter_params['oauth_info']

            if not 'stream_filter' in twitter_params:
                is_correct = False
            elif type(twitter_params['stream_filter']) is not dict:
                is_correct = False
            #else:
            #    stream_filter = twitter_params['stream_filter']

            if not 'endpoint' in twitter_params:
                is_correct = False
            elif type(twitter_params['endpoint']) is not dict:
                is_correct = False
        except:
            is_correct = False

    if is_correct:
        for part in oauth_info:
            if not part in twitter_params['oauth_info']:
                is_correct = False
                break
            if not twitter_params['oauth_info'][part]:
                is_correct = False
                break
            try:
                oauth_info[part] = str(twitter_params['oauth_info'][part])
            except:
                is_correct = False
                break

    if is_correct:
        is_correct = False
        for part in stream_filter_basic:
            if part in twitter_params['stream_filter']:
                if twitter_params['stream_filter'][part]:
                    try:
                        stream_filter[part] = str(twitter_params['stream_filter'][part])
                    except:
                        is_correct = False
                        break
                    if stream_filter[part]:
                        is_correct = True

    if is_correct:
        for part in stream_filter_other:
            if part in twitter_params['stream_filter']:
                if twitter_params['stream_filter'][part]:
                    try:
                        stream_filter[part] = str(twitter_params['stream_filter'][part])
                    except:
                        is_correct = False
                        break

    if is_correct:
        for part in endpoint:
            if not part in twitter_params['endpoint']:
                is_correct = False
                break
            if not twitter_params['endpoint'][part]:
                is_correct = False
                break
            try:
                endpoint[part] = str(twitter_params['endpoint'][part])
            except:
                is_correct = False
                break

    if is_correct:
        try:
            d = make_stream_connection()
        except:
            is_correct = False

    if is_correct:
        reactor.run()
'''

#oauth_info = {}
from search_auth import oauth_info

if __name__ == '__main__':
    searches = RequestQueue()
    processor = QueueProcessor(searches)
    resource = QueuedResource()
    resource.set_processor(processor)
    reactor.listenTCP(8080, server.Site(resource))
    reactor.run()
