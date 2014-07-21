#!/usr/bin/env python

import sys, os, time, json, argparse
import logging, logging.handlers
import urllib, urllib2, select
import oauth2 as oauth
import signal, atexit
import ctypes

'''
this is for authoring a twitter-app for sending tweets.

Authorize an app for a user to be able to send tweets on behalf of that user:
* phase one: 
    gets: consumer_key, consumer_secret
    returns: oauth_token_tmp, oauth_token_secret_tmp, authorize_url
* phase_two:
    gets: consumer_key, consumer_secret, oauth_token_tmp, oauth_token_secret_tmp, verifier_pin
    returns: oauth_token, oauth_token_secret

Send a tweet:
    gets: consumer_key, consumer_secret, oauth_token, oauth_token_secret; message, reply_to_id, ...
    saves: puts the tweet into es/cd-core
    returns: id of tweet
'''

class RequestToken():
    #oauth_info = {
    #    'consumer_key': 'have-to-have',
    #    'consumer_secret': 'have-to-have',
    #    'access_token_key': '',
    #    'access_token_secret': '',
    #}

    def __init__(self, oauth_info):
        self.oauth_info = oauth_info

    REQ_URL_REQUEST_TOKEN = 'https://api.twitter.com/oauth/request_token'

    def ask_token(self):
        request_token_url = self.REQ_URL_REQUEST_TOKEN + '?oauth_callback=oob&x_auth_access_type=write'

        consumer = oauth.Consumer(key=self.oauth_info['consumer_key'],secret=self.oauth_info['consumer_secret'])
        client = oauth.Client(consumer)
        try:
            resp, content = client.request(request_token_url, 'GET')
        except exc:
            return None

        #oauth_token=USED_FOR_TMP_OAUTH_TOKEN_AND_FOR_VERIFIER_URL&oauth_token_secret=USED_FOR_TMP_OAUTH_TOKEN_SECRET&oauth_callback_confirmed=true
        print(content)

        return content

        #for pin/verifier, ask at
        #https://api.twitter.com/oauth/authorize?oauth_token=TMP_OAUTH_TOKEN

class AccessToken():

    verifier = 'the_pin_that_a_user_gets_from_twitter'

    oauth_info = {
        'consumer_key': 'the_initial_consumer_key',
        'consumer_secret': 'the_initial_consumer_secret',
        'access_token_key': 'the_temporary_oauth_token',
        'access_token_secret': 'the_temporary_oauth_token_secret',
    }

    REQ_URL_ACCESS_TOKEN = 'https://api.twitter.com/oauth/access_token'

    def get_req_params(self):
        return urllib.urlencode({'oauth_verifier': self.verifier})

    def get_oauth_header(self):

        oauth_consumer = oauth.Consumer(key=self.oauth_info['consumer_key'], secret=self.oauth_info['consumer_secret'])
        oauth_token = oauth.Token(key=self.oauth_info['access_token_key'], secret=self.oauth_info['access_token_secret'])

        oauth_params = {}
        oauth_params['oauth_version'] = '1.0'
        oauth_params['oauth_nonce'] = oauth.generate_nonce()
        oauth_params['oauth_timestamp'] = int(time.time())

        req_url = self.REQ_URL_ACCESS_TOKEN + '?' + self.get_req_params()

        req = oauth.Request(method='POST', parameters=oauth_params, url=req_url)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), oauth_consumer, oauth_token)

        return req.to_header()['Authorization'].encode('utf-8')

    def get_headers(self):
        conn_headers = {}

        conn_headers['Host'] = 'api.twitter.com'
        conn_headers['Authorization'] = self.get_oauth_header()
        conn_headers['User-Agent'] = 'Newstwister'
        conn_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        #for key in conn_headers: # for Twisted-based requests
        #    conn_headers[key] = [conn_headers[key]]

        return conn_headers

    def make_req(self):

        try:
            req = urllib2.Request(self.REQ_URL_ACCESS_TOKEN, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            req_result = response.read()

            #'oauth_token=AUTHORIZED_OAUTH_TOKEN&oauth_token_secret=AUTHORIZED_OAUTH_TOKEN_SECRET&user_id=ID_OF_USER&screen_name=SCREEN_NAME_OF_USER'
            print('req_result: ' + str(req_result))

        except Exception as exc:
            print('exception: ' + str(exc))
            print('exception: ' + str(exc.reason))
            pass




class SendTweet():

    oauth_info = {
        'consumer_key': 'the_initial_consumer_key',
        'consumer_secret': 'the_initial_consumer_secret',
        'access_token_key': 'the_authorized_oauth_token',
        'access_token_secret': 'the_authorized_oauth_token_secret',
    }

    REQ_URL_SEND_TWEET = 'https://api.twitter.com/1.1/statuses/update.json'

    tweet_params = {
        'message': None,
        'status_id': None,
    }

    def set_req_params(self, message, status_id):
        self.tweet_params['message'] = message
        self.tweet_params['status_id'] = status_id

    def get_req_params(self):
        params = {'status': str(self.tweet_params['message'])}

        if self.tweet_params['status_id']:
            params['in_reply_to_status_id'] = str(self.tweet_params['status_id'])

        return urllib.urlencode(params)

    def get_oauth_header(self):

        oauth_consumer = oauth.Consumer(key=self.oauth_info['consumer_key'], secret=self.oauth_info['consumer_secret'])
        oauth_token = oauth.Token(key=self.oauth_info['access_token_key'], secret=self.oauth_info['access_token_secret'])

        oauth_params = {}
        oauth_params['oauth_version'] = '1.0'
        oauth_params['oauth_nonce'] = oauth.generate_nonce()
        oauth_params['oauth_timestamp'] = int(time.time())

        req_url = self.REQ_URL_SEND_TWEET + '?' + self.get_req_params()

        req = oauth.Request(method='POST', parameters=oauth_params, url=req_url)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), oauth_consumer, oauth_token)
        return req.to_header()['Authorization'].encode('utf-8')

    def get_headers(self):
        conn_headers = {}

        conn_headers['Host'] = 'api.twitter.com'
        conn_headers['Authorization'] = self.get_oauth_header()
        conn_headers['User-Agent'] = 'Newstwister'
        conn_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        #for key in conn_headers: # for Twisted-based requests
        #    conn_headers[key] = [conn_headers[key]]

        return conn_headers

    def make_req(self):

        try:
            req = urllib2.Request(self.REQ_URL_SEND_TWEET, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            req_result = response.read()

            #{_standard_tweet_structure_: "id_str":"491186627696680960", ...}
            print('req_result: ' + str(req_result))

        except Exception as exc:
            print('exception: ' + str(exc))
            print('exception: ' + str(exc.reason))
            pass


class RequestProcessor():

    def _write_error(self, msg):
        sys.stdout.write(str(msg) + '\n')
        sys.exit(1)

    def _write_json(self, data):
        sys.stdiut.write(str(json.dumps(data)) + '\n')
        sys.exit(0)

    def run_pipe(self, run_specs, request_params, oauth_info):

        request_type = run_specs.get_request_type()

        if 'auth_start' == request_type:
            negotiator = RequestToken(oauth_info)
            result = negotiator.ask_token(request_params)
            self._write_json(result)

        if 'auth_finish' == request_type:
            negotiator = AccessToken(oauth_info)
            result = negotiator.ask_token(request_params)
            self._write_json(result)

        if 'send_tweet' == request_type:
            save_url = run_specs.get_save_url()
            if not save_url:
                self._write_error('no save-url was provided')

            negotiator = SendTweet(oauth_info)
            result = negotiator.ask_token(request_params)

            elsd = ElsDepositor(request_type, save_url)
            res = elsd.save_result_data(data)
            if not res:
                self._write_error('error during data-saving processing')

            self._write_json(res)

        self._write_error('unknown request type')
        return

oauth_info_base = {
    'consumer_key': True,
    'consumer_secret': True,
    'access_token_key': False,
    'access_token_secret': False,
}
oauth_info_data = {}

payload_params = {}

if __name__ == '__main__':

    run_specs.use_specs() # for request_type, save_url, if any

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
        except:
            is_correct = False

    if is_correct:
        oauth_set = twitter_params['oauth_info']
        one_oauth_use = {}

        for part in oauth_info_base:
            one_oauth_use[part] = ''

            is_required = oauth_info_base[part]
            if is_required:
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
            oauth_info_data = one_oauth_use

    if not oauth_info_data:
        is_correct = False

    if is_correct:
        if 'payload' not in twitter_params:
            is_correct = False
        elif type(twitter_params['payload']) is not dict:
            is_correct = False

    if is_correct:
        for part in twitter_params['payload']:
            payload_params[part] = twitter_params['payload'][part]

    if is_correct:
        processor = RequestProcessor()
        processor.run_pipe(run_specs, payload_params, oauth_info_data)

