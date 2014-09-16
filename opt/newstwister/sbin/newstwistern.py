#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, time, json, argparse
import logging, logging.handlers
import urllib, urllib2, select
import oauth2 as oauth
import signal, atexit
import ctypes
import datetime

from pprint import pformat

from zope.interface import Interface, implements

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed
from twisted.internet.protocol import Protocol
from twisted.internet.ssl import ClientContextFactory
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer
from twisted.python.log import err

try:
    import setproctitle
except:
    if not str(sys.platform).lower().startswith('linux'):
        sys.stderr.write('either the setproctitle module has to be available, or the OS has to be Linux')
        sys.exit(1)

DISCONNECT_INTERVAL_MIN = 10
DISCONNECT_COUNT_MAX = 5

SAVE_URL = 'http://localhost:9200/newstwister/tweets/'
NOTICE_URL = 'http://localhost:9200/newstwister/notices/'
NOTICE_TIMEOUT = 5

PR_SET_NAME = 15
NODE_NAME = 'newstwistern'

to_debug = False
DEBUG_PATH = '/tmp/newstwister_node.debug'

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
            'save_url': SAVE_URL,
            'notice_url': NOTICE_URL,
            'log_path': None
        }
    def get_specs(self):
        return self.specs

    def use_specs(self):
        global to_debug

        parser = argparse.ArgumentParser()
        parser.add_argument('-s', '--save_url', help='url for saving the tweets')
        parser.add_argument('-n', '--notice_url', help='url for saving error notices')
        parser.add_argument('-l', '--log_path', help='path to log file')
        parser.add_argument('-d', '--debug', help='whether to write debug info', action='store_true')

        args = parser.parse_args()
        if args.save_url:
            self.specs['save_url'] = args.save_url
        if args.log_path:
            self.specs['log_path'] = args.log_path
        if args.debug:
            to_debug = True

save_specs = SaveSpecs()

class Params():
    def get_post_params(self):
        global stream_filter

        post_params = {}
        post_params['stall_warnings'] = 'true'

        for one_key in stream_filter:
            try:
                post_params[one_key] = stream_filter[one_key].decode('utf-8')
            except:
                pass

        return post_params

    def get_oauth_header(self):
        global oauth_info

        oauth_consumer = oauth.Consumer(key=oauth_info['consumer_key'], secret=oauth_info['consumer_secret'])
        oauth_token = oauth.Token(key=oauth_info['access_token_key'], secret=oauth_info['access_token_secret'])

        oauth_params = {}
        oauth_params['oauth_version'] = '1.0'
        oauth_params['oauth_nonce'] = oauth.generate_nonce()
        oauth_params['oauth_timestamp'] = int(time.time())

        req_url = 'https://stream.twitter.com/1.1/statuses/filter.json' + '?' + urllib.urlencode(self.get_post_params())

        req = oauth.Request(method='POST', parameters=oauth_params, url=req_url)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), oauth_consumer, oauth_token)
        return req.to_header()['Authorization'].encode('utf-8')

    def get_headers(self):
        conn_headers = {}
        conn_headers['Host'] = ['stream.twitter.com']
        conn_headers['Authorization'] = [self.get_oauth_header()]
        conn_headers['User-Agent'] = ['Newstwister']
        conn_headers['Content-Type'] = ['application/x-www-form-urlencoded']

        return conn_headers

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

# Resolving links from URL-shortened forms

class RslClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class TweetResolver(object):
    def __init__(self, tweet):
        self.tweet = tweet
        self.last_url = ''
        self.last_type = ''
        self.last_host = ''
        self.url_rank = 0
        self.urls = []
        return # this processing causes too big cpu use

        if (type(tweet) is dict) and ('entities' in tweet) and (type(tweet['entities']) is dict):
            report_entities = tweet['entities']
        else:
            report_entities = {}

        if report_entities:
            all_url_sets = []

            for link_entity_type in ['urls', 'media']:
                if (link_entity_type in report_entities) and report_entities[link_entity_type]:
                    all_url_sets.append(report_entities[link_entity_type])
            for one_url_set in all_url_sets:
                if one_url_set and (type(one_url_set) in [list, tuple]):
                    for one_url in one_url_set:
                        if type(one_url) is not dict:
                            continue
                        if 'expanded_url' not in one_url:
                            continue
                        self.urls.append(one_url)

    def get_type(self, url):
        if url.startswith('https'):
            return 'https'
        if url.startswith('http'):
            return 'http'
        return ''

    def get_host(self, url):

        ind_host_start = url.find(':')
        if -1 >= ind_host_start:
            return ''

        ind_host_start = ind_host_start + 3
        url_host = url[ind_host_start:]

        ind_host_end = url_host.find('/')
        if 0 <= ind_host_end:
            url_host = url_host[:ind_host_end]

        return str(url_host)

    def get_headers(self, host):
        conn_headers = {}
        conn_headers['Host'] = [host]
        conn_headers['User-Agent'] = ['Newstwister']
        conn_headers['Connection'] = ['close']

        return conn_headers

    def dispatch_tweet(self):
        if self.url_rank >= len(self.urls):
            tws = TweetSaver()
            tws.save_tweet(self.tweet)
            return

        self.last_url = self.urls[self.url_rank]['expanded_url']
        self.last_type = self.get_type(self.last_url)
        self.last_host = self.get_host(self.last_url)

        self.resolve_url(self.last_url)

    def update_tweet(self, current_redirect):
        if current_redirect:
            self.last_url = current_redirect
            self.last_type = self.get_type(self.last_url)
            self.last_host = self.get_host(self.last_url)

            self.resolve_url(self.last_url)
            return

        else:
            self.urls[self.url_rank]['resolved_url'] = self.last_url

            self.url_rank += 1
            self.dispatch_tweet()
            return

    def resolve_url(self, redir_url):
        contextFactory = RslClientContextFactory()
        agent = Agent(reactor, contextFactory)

        try:
            d_rs = agent.request(
                'HEAD',
                str(redir_url),
                Headers(self.get_headers(self.last_host)),
                None)
        except Exception, exc:
            debug_msg('exc in url (' + str(redir_url) + ') resolving: ' + str(exc))
            self.update_tweet(None)

        borders = RslResponseBorders(self)

        d_rs.addCallback(borders.cbRequest)
        d_rs.addBoth(borders.cbShutdown)

        return d_rs

class RslResponseBorders():
    def __init__(self, resolver):
        self.resolver = resolver

    def cbRequest(self, response):
        debug_msg('Rsl response version: ' + str(response.version))
        debug_msg('Rsl response code: ' + str(response.code))
        debug_msg('Rsl response phrase: ' + str(response.phrase))
        debug_msg('Rsl response headers:')
        debug_msg(pformat(list(response.headers.getAllRawHeaders())))

        redir_url = ''
        try:
            got_locations = list(response.headers.getRawHeaders('location'))
            if len(got_locations):
                redir_url = got_locations[0]
        except:
            redir_url = ''

        if redir_url.startswith('/'):
            redir_url = self.resolver.last_type + '://' + self.resolver.last_host + redir_url

        resolver = self.resolver
        self.resolver = None

        resolver.update_tweet(redir_url)

    def cbShutdown(self, ignored):
        debug_msg(str(ignored))
        debug_msg('shutting down resolver connection')

        try:
            self.resolver.update_tweet(None)
        except:
            pass

# Part putting tweets into ES

class ElsClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class ElsResponser(Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.buffer = ''
        self.count = 0

    def dataReceived(self, data):
        debug_msg('got next data from ES: ' + str(data))
        pass

    def connectionLost(self, reason):
        debug_msg('Finished receiving ES response: ' + str(reason.getErrorMessage()))
        self.finished.callback(None)

class TweetSaver(object):
    def __init__(self):
        global save_specs

        self.save_url = save_specs.get_specs()['save_url']
        if not self.save_url.endswith('/'):
            self.save_url += '/'

    def get_headers(self):
        host = self.save_url[(self.save_url.find(':')+3):]
        host = host[:host.find('/')]

        conn_headers = {}
        conn_headers['Host'] = [host]
        conn_headers['User-Agent'] = ['Newstwister']
        conn_headers['Content-Type'] = ['application/json']
        conn_headers['Accept'] = ['application/json']

        return conn_headers

    def save_tweet(self, tweet):
        global stream_spec_original

        tweet_id = tweet.get('id_str')
        if not tweet_id:
            return False
        save_data = {}
        save_data['request'] = None
        save_data['type'] = 'stream'
        save_data['endpoint'] = endpoint
        save_data['filter'] = stream_spec_original
        save_data['tweet'] = tweet

        tweet_data = json.dumps(save_data)

        contextFactory = ElsClientContextFactory()
        agent = Agent(reactor, contextFactory)

        send_url = self.save_url + str(tweet_id)

        d_es = agent.request(
            'POST',
            send_url,
            Headers(self.get_headers()),
            StringProducer(tweet_data))

        borders = ElsResponseBorders()
        d_es.addCallback(borders.cbRequest)
        d_es.addBoth(borders.cbShutdown)

        return d_es

class ElsResponseBorders():
    def cbRequest(self, response):

        debug_msg('Els response version: ' + str(response.version))
        debug_msg('Els response code: ' + str(response.code))
        debug_msg('Els response phrase: ' + str(response.phrase))
        debug_msg('Els response headers:')
        debug_msg(pformat(list(response.headers.getAllRawHeaders())))

        finished = Deferred()
        response.deliverBody(ElsResponser(finished))
        return finished

    def cbShutdown(self, ignored):
        debug_msg(str(ignored))
        debug_msg('shutting down els connection')
        pass

# Part taking tweets from Twitter

class TwtClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

class TweetProcessor(Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.buffer = ''
        self.count = 0

    def _process_tweet(self, data):
        global disconnect_code
        global logger

        self.buffer += data

        message_set = []
        if data.endswith('\r\n') and self.buffer.strip(): # some finished message(s)
            for buffer_part in self.buffer.split('\r\n'):
                buffer_part = buffer_part.strip()
                if not buffer_part:
                    continue
                try:
                    curr_message = json.loads(buffer_part)
                except:
                    logger.warning('twitter message issue -- not json form: ' + str(buffer_part)[:40])
                    debug_msg('message apparently non-json:\n' + str(buffer_part))
                    continue

                if (type(curr_message) is not dict):
                    logger.warning('twitter message issue -- not dict form: ' + str(buffer_part)[:40])
                    debug_msg('apparently non-dict message:\n' + str(buffer_part))
                    continue

                message_set.append(curr_message)

            self.buffer = ''

        for message in message_set:

            # status messages
            if message.get('limit'): # error (not a tweet), over the rate limit
                limit_msg = 'rate limit over, count of missed tweets: ' + str(message['limit'].get('track'))
                debug_msg(limit_msg)
                logger.warning(limit_msg)
            elif message.get('disconnect'): # error (not a tweet), got disconnected
                disconnect_msg = 'disconnected: (' + str(message['disconnect'].get('code')) + ') '
                disconnect_msg += str(message['disconnect'].get('reason'))
                debug_msg(disconnect_msg)
                logger.warning(disconnect_msg)
                # should restart the read cycle if not severe reason for disconnect
                disconnect_code = message['disconnect'].get('code')
                try:
                    disconnect_code = int(disconnect_code)
                except:
                    pass

            elif message.get('warning'): # warning (not a tweet)
                warning_msg = 'warning: ' + str(message['warning'].get('message'))
                debug_msg(warning_msg)
                logger.warning(warning_msg)
                pass

            # actual tweet
            else:
                # putting the tweet into elastic search
                twr = TweetResolver(message)
                twr.dispatch_tweet()

                '''
                # outputting the tweet, development purposes only
                tid = message.get('id_str')
                user = message.get('user')
                uid = str(user['id_str']) if (user and ('id_str' in user)) else ''
                uname = str(user['name'].encode('utf-8')) if (user and ('name' in user)) else ''
                ulocation = str(user['location'].encode('utf-8')) if (user and ('location' in user)) else ''

                t_coords = str(message.get('coordinates'))
                t_geo = str(message.get('geo'))
                t_place = str(message.get('place'))

                msg_beg = 'https://twitter.com/cdeskdev/status/' + str(tid) + '\n'
                msg_geo = 'coords: ' + t_coords + ', geo: ' + t_geo + ', place: ' + t_place + '\n'
                msg_mid = '' + uid + '/' + uname + '/' + ulocation + ': '
                msg_end = message.get('text').encode('utf-8')
                print(msg_beg + msg_geo + msg_mid + msg_end)
                print(str(message.get('entities')) + '\n')
                '''

    def dataReceived(self, data):

        self._process_tweet(data)

        '''
        #development purposes only
        self.count += 1
        print('count: ' + str(self.count))
        '''

    def connectionLost(self, reason):
        debug_msg('Finished receiving Twitter stream: ' + str(reason.getErrorMessage()))
        self.finished.callback(None)

twitter_got_connected = False
class TwtResponseBorders():
    def cbRequest(self, response):
        global logger
        global twitter_got_connected
        twitter_got_connected = True

        debug_msg('Twt response version:' + str(response.version))
        debug_msg('Twt response code:' + str(response.code))
        debug_msg('Twt response phrase:' + str(response.phrase))
        debug_msg('Twt response headers:')
        debug_msg(pformat(list(response.headers.getAllRawHeaders())))

        if '200' != str(response.code):
            logger.warning('Twitter disliked stream connection: ' + str(response.code))
            notify_stopped(True, True, 'twitter dislikes the stream connection')
            close_reactor()
            return

        finished = Deferred()
        response.deliverBody(TweetProcessor(finished))
        return finished

    def cbShutdown(self, ignored):
        global forced_quit
        global logger
        global twitter_got_connected

        debug_msg(ignored)
        debug_msg('shutting twt down')
        if not forced_quit:
            if twitter_got_connected:
                debug_msg('twitter connection to be reconnected later')
                logger.warning('Twitter connection got down')
                reactor.callLater(0.5, adapt_to_disconnect)
            else:
                debug_msg('twitter connection to be closed')
                logger.warning('Twitter refused stream connection')
                notify_stopped(True, True, 'twitter refuses the stream connection')
                close_reactor()

def close_reactor():
    try:
        reactor.disconnectAll()
    except:
        pass

    try:
        reactor.stop()
    except:
        pass

    cleanup()

def notify_stopped(send_message, synchronous, message_text):
    global save_specs
    global endpoint

    # we shall trigger a global notification action here
    if not send_message:
        return
    if not synchronous:
        debug_msg('notification message should be sent the synchronous way')
        return # by now, we only send the message the synchronous way, as the node is stopped immediately after that

    notice_url = save_specs.get_specs()['notice_url']
    if not notice_url.endswith('/'):
        notice_url += '/'

    timestamp = urllib.quote_plus(datetime.datetime.now().isoformat())
    notice_url += str(timestamp)

    try:
        endpoint_value = str(endpoint['endpoint_id'])
    except:
        endpoint_value = endpoint

    params = {}
    params['feed_type'] = 'tweet'
    params['channel'] = {
        'type': 'stream',
        'value': endpoint_value,
        'request': None,
    }
    params['message'] = message_text

    try:
        post_data = json.dumps(params)
        req = urllib2.Request(notice_url, post_data, {'Content-Type': 'application/json'})
        response = urllib2.urlopen(req, timeout=NOTICE_TIMEOUT)
        notice_status = response.read()
    except Exception as exc:
        err_notice = 'can not send notice message: ' + str(exc)
        try:
            err_part = str(exc.message).strip()
            if err_part:
                err_notice += ', ' + err_part
        except:
            pass
        try:
            err_part = str(exc.read()).strip()
            if err_part:
                err_notice += ', ' + err_part
        except:
            pass
        debug_msg(err_notice)

    return

disconnect_last = time.time()
disconnect_count = 0
disconnect_code = None
def adapt_to_disconnect():
    global disconnect_last
    global disconnect_count
    global disconnect_code

    to_stop = False

    # for disconnect codes, look at:
    # https://dev.twitter.com/docs/streaming-apis/messages#Disconnect_messages_disconnect
    disconnect_count += 1
    if disconnect_code in [12]:
        disconnect_count = 1

    current_time = time.time()
    if current_time > (disconnect_last + DISCONNECT_INTERVAL_MIN):
        disconnect_count = 1
    if disconnect_count > DISCONNECT_COUNT_MAX:
        to_stop = True
        debug_msg('stopping, since too many (' + str(disconnect_count) + ') disconnects in short intervals')

    if disconnect_code in [2, 6, 7, 9]:
        to_stop = True
        debug_msg('stopping, since disconnect code considered severe: ' + str(disconnect_code))

    if to_stop:
        notify_stopped(True, True, 'too many disconnections from the twitter stream')
        close_reactor()
        return

    reactor.callLater(0.5, restart_stream)

def restart_stream():
    global d
    d = make_stream_connection()

def make_stream_connection():
    global twitter_got_connected

    twitter_got_connected = False
    disconnect_code = None
    debug_msg('making stream connection')

    params = Params()
    post_params = params.get_post_params()
    post_data = urllib.urlencode(post_params)
    debug_msg('using stream params: ' + str(post_params))

    contextFactory = TwtClientContextFactory()
    agent = Agent(reactor, contextFactory)

    d = agent.request(
        'POST',
        'https://stream.twitter.com/1.1/statuses/filter.json',
        Headers(params.get_headers()),
        StringProducer(post_data))

    borders = TwtResponseBorders()
    d.addCallback(borders.cbRequest)
    d.addBoth(borders.cbShutdown)

    return d

# General script passage

forced_quit = False
def process_quit(signal_number, frame):
    global d
    global forced_quit

    forced_quit = True

    debug_msg('stream process asked to quit')

    try:
        d.cancel()
    except:
        pass

    close_reactor()
    cleanup()

def cleanup():
    logger.info('Twitter stream ends')
    debug_msg(str(os.getpid()))
    debug_msg('stopping the stream process')
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
stream_spec_original = None

if __name__ == '__main__':

    if not set_proc_name():
        sys.exit(1)

    save_specs.use_specs()

    log_path = save_specs.get_specs()['log_path']
    setup_logger(log_path)

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
            elif type(twitter_params['oauth_info']) is not dict:
                is_correct = False

            if not 'stream_filter' in twitter_params:
                is_correct = False
            elif type(twitter_params['stream_filter']) is not dict:
                is_correct = False

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
        if 'stream_spec_original' in twitter_params:
            if type(twitter_params['stream_spec_original']) is dict:
                stream_spec_original = twitter_params['stream_spec_original']

    if is_correct:
        try:
            d = make_stream_connection()
        except:
            is_correct = False

    if is_correct:
        reactor.run()

