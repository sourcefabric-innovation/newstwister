#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, time, json
import urllib
import oauth2 as oauth
import signal

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

from stw_auth import oauth_info
from stw_feed import stream_filter


class Params():
    def get_post_params(self):
        global stream_filter

        post_params = {}
        post_params['include_entities'] = 0
        post_params['stall_warning'] = 'true'

        for one_key in stream_filter:
            post_params[one_key] = stream_filter[one_key].decode('utf-8')

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
        conn_headers['User-Agent'] = ['testing steamer']
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
        print('got next data from ES: ' + str(data))

    def connectionLost(self, reason):
        print 'Finished receiving ES response:', reason.getErrorMessage()
        self.finished.callback(None)

class TweetSaver(object):
    def __init__(self):
        self.els_proto = 'http'
        self.els_domain = 'localhost'
        self.els_port = 9200

        self.server_url = self.els_proto + '://' + self.els_domain + ':' + str(self.els_port) + '/'
        self.index_name = 'citizen_desk'
        self.doctype_name = 'tweets'

        self.base_url = self.server_url + '/' + self.index_name + '/' + self.doctype_name + '/'

    def get_headers(self):
        conn_headers = {}
        conn_headers['Host'] = [self.els_domain + ':' + str(self.els_port)]
        conn_headers['User-Agent'] = ['stweamer']
        conn_headers['Content-Type'] = ['application/x-www-form-urlencoded']
        conn_headers['Accept'] = ['application/json']

        return conn_headers

    def save_tweet(self, message):
        tweet_id = message.get('id_str')
        if not tweet_id:
            return False
        tweet_data = json.dumps(message)

        contextFactory = ElsClientContextFactory()
        agent = Agent(reactor, contextFactory)

        send_url = self.base_url + str(tweet_id)

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

        print 'Els response version:', response.version
        print 'Els response code:', response.code
        print 'Els response phrase:', response.phrase
        print 'Els response headers:'
        print pformat(list(response.headers.getAllRawHeaders()))
        finished = Deferred()
        response.deliverBody(ElsResponser(finished))
        return finished

    def cbShutdown(self, ignored):
        print(ignored)
        print('shutting down els connection')

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

        self.buffer += data
        if data.endswith('\r\n') and self.buffer.strip(): # some finished message
            message = json.loads(self.buffer)
            self.buffer = ''

            # status messages
            if message.get('limit'): # error (not a tweet), over the rate limit
                print('rate limit over, count of missed tweets: ' + str(message['limit'].get('track')))
            elif message.get('disconnect'): # error (not a tweet), got disconnected
                print('disconnected: ' + str(message['disconnect'].get('reason')))
                # should restart the read cycle!
            elif message.get('warning'): # warning (not a tweet)
                print 'warning: ' + str(message['warning'].get('message'))

            # actual tweet
            else:
                # putting the tweet into elastic search
                tws = TweetSaver()
                tws.save_tweet(message)

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

    def dataReceived(self, data):

        self._process_tweet(data)

        #self.count += 1
        #print('count: ' + str(self.count))

    def connectionLost(self, reason):
        print 'Finished receiving Twitter stream:', reason.getErrorMessage()
        self.finished.callback(None)

class TwtResponseBorders():
    def cbRequest(self, response):

        print 'Twt response version:', response.version
        print 'Twt response code:', response.code
        print 'Twt response phrase:', response.phrase
        print 'Twt response headers:'
        print pformat(list(response.headers.getAllRawHeaders()))
        finished = Deferred()
        response.deliverBody(TweetProcessor(finished))
        return finished

    def cbShutdown(self, ignored):
        print(ignored)
        print('shutting twt down')
        #reactor.stop()

def make_stream_connection():
    params = Params()
    post_data = urllib.urlencode(params.get_post_params())

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

def signal_handler(signal_number, frame):
    global d

    d.cancel()
    print(os.getpid())
    #signal.signal(signal.SIGINT, signal_handler)
    #signal.signal(signal.SIGTERM, process_quit)

    reactor.disconnectAll()

    process_quit(signal_number, frame)

def process_quit(signal_number, frame):
    print(os.getpid())
    print('stopping the process')
    os._exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, process_quit)

    d = make_stream_connection()

    reactor.run()

