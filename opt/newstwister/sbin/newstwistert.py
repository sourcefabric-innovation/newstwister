#!/usr/bin/env python

import sys, os, time, json, argparse
import logging, logging.handlers
import urllib, urllib2, select
import oauth2 as oauth
import signal, atexit
import ctypes

'''
this is for authoring a twitter-app for sending tweets, and fot the actual tweet sending too.

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

DEBUG_PATH = '/tmp/newstwister_tweet.debug'

def debug_msg(msg):
    global run_specs

    if not run_specs.get_to_debug():
        return

    try:
        fh = open(DEBUG_PATH, 'a+')
        fh.write(str(msg) + '\n')
        fh.flush()
        fh.close()
    except:
        pass

class RunSpecs():
    def __init__(self):
        self.specs = {
            'request_type': None,
            'save_url': None,
            'to_debug': False,
        }

    def use_specs(self):
        global to_debug

        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--request_type', help='type of the requested action', default='')
        parser.add_argument('-s', '--save_url', help='url for saving result data', default='')
        parser.add_argument('-d', '--debug', help='whether to write debug info', action='store_true')

        args = parser.parse_args()
        if args.request_type:
            self.specs['request_type'] = args.request_type
        if args.save_url:
            self.specs['save_url'] = args.save_url
        if args.debug:
            self.specs['to_debug'] = True

    def get_request_type(self):
        return self.specs['request_type']
    def get_save_url(self):
        return self.specs['save_url']
    def get_to_debug(self):
        return self.specs['to_debug']

run_specs = RunSpecs()

class ElsDepositor(object):
    def __init__(self, request_type, save_url):
        self.request_type = request_type
        self.save_url = save_url

    def save_result_data(self, data):
        if 'send_tweet' == self.request_type:
            res = self.send_request(self.save_url, json.dumps(data), {'Content-Type': 'application/json'})
            return res

        err_msg = 'ElsDepositor: unknown data type for saving'
        debug_msg(err_msg)
        return (False, err_msg)

    def send_request(self, save_url, save_body, save_headers):
        save_status = None

        try:
            req = urllib2.Request(save_url, save_body, save_headers)
            response = urllib2.urlopen(req)
            save_status = response.read()
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
            err_msg = 'ElsDepositor: can not save the data: ' + str(exc) + str(exc_other)
            debug_msg(err_msg)
            return (False, err_msg)

        return (True, save_status)

class RequestToken(object):
    #oauth_info = {
    #    'consumer_key': 'the_app_consumer_key',
    #    'consumer_secret': 'the_app_consumer_secret',
    #    'access_token_key': '',
    #    'access_token_secret': '',
    #}

    REQ_URL_REQUEST_TOKEN = 'https://api.twitter.com/oauth/request_token'

    def __init__(self, oauth_info, params):
        self.oauth_info = oauth_info
        self.request_params = request_params

    def get_request_token(self):
        if (not self.oauth_info['consumer_key']) or (not self.oauth_info['consumer_secret']):
            err_msg = 'RequestToken: consumer app key not provided'
            debug_msg(err_msg)
            return (False, err_msg)

        request_token_url = self.REQ_URL_REQUEST_TOKEN + '?oauth_callback=oob&x_auth_access_type=write'

        consumer = oauth.Consumer(key=self.oauth_info['consumer_key'],secret=self.oauth_info['consumer_secret'])
        client = oauth.Client(consumer)
        try:
            resp, content = client.request(request_token_url, 'GET')
        except exc:
            err_msg = str(exc)
            try:
                err_msg += ', ' + str(exc.reason)
            except:
                pass
            err_msg = 'RequestToken: can not get request token: ' + err_msg
            debug_msg(err_msg)
            return (False, err_msg)

        #oauth_token=USED_FOR_TMP_OAUTH_TOKEN_AND_FOR_VERIFIER_URL&oauth_token_secret=USED_FOR_TMP_OAUTH_TOKEN_SECRET&oauth_callback_confirmed=true
        debug_msg('RequestToken: got request token content: ' + str(content))

        try:
            parsed_content = urllib2.urlparse.parse_qs(content)
        except:
            err_msg = 'RequestToken: can not parse the received request token'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content) is not dict):
            err_msg = 'RequestToken: the received request token is incorrect'
            debug_msg(err_msg)
            return (False, err_msg)

        required_parts = ['oauth_token', 'oauth_token_secret']
        for one_part in required_parts:
            if (one_part not in parsed_content) or (not parsed_content):
                err_msg = 'RequestToken: the received request token is incomplete, missing: ' + str(one_part)
                debug_msg(err_msg)
                return (False, err_msg)

        oauth_token_key = None
        oauth_token_secret = None
        #for pin/verifier, ask at
        #https://api.twitter.com/oauth/authorize?oauth_token=TMP_OAUTH_TOKEN
        pin_url = None

        if (type(parsed_content['oauth_token']) in (list, tuple)) and parsed_content['oauth_token']:
            for part in parsed_content['oauth_token']:
                if part:
                    oauth_token_key = part
                    break
        if not oauth_token_key:
            err_msg = 'RequestToken: the received request is without oauth_token'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content['oauth_token_secret']) in (list, tuple)) and parsed_content['oauth_token_secret']:
            for part in parsed_content['oauth_token_secret']:
                if part:
                    oauth_token_secret = part
                    break
        if not oauth_token_secret:
            err_msg = 'RequestToken: the received request is without oauth_token_secret'
            debug_msg(err_msg)
            return (False, err_msg)
        pin_url = 'https://api.twitter.com/oauth/authorize?oauth_token=' + str(oauth_token_key)

        result_data = {
            'oauth_token_key': str(oauth_token_key),
            'oauth_token_secret': str(oauth_token_secret),
            'pin_url': str(pin_url),
        }

        debug_msg('RequestToken: result data: ' + json.dumps(result_data))

        return (True, result_data)

class AccessToken(object):

    #verifier = 'the_pin_that_a_user_gets_from_twitter'

    #oauth_info = {
    #    'consumer_key': 'the_app_consumer_key',
    #    'consumer_secret': 'the_app_consumer_secret',
    #    'access_token_key': 'the_temporary_oauth_token',
    #    'access_token_secret': 'the_temporary_oauth_token_secret',
    #}

    REQ_URL_ACCESS_TOKEN = 'https://api.twitter.com/oauth/access_token'

    def __init__(self, oauth_info, request_params):
        self.oauth_info = oauth_info
        self.request_params = request_params
        self.verifier = None
        if 'verifier' in request_params:
            try:
                self.verifier = str(request_params['verifier'])
            except:
                self.verifier = None

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

    def get_access_token(self):
        if (not self.oauth_info['consumer_key']) or (not self.oauth_info['consumer_secret']):
            err_msg = 'AccessToken: consumer app data not provided'
            debug_msg(err_msg)
            return (False, err_msg)
        if (not self.oauth_info['access_token_key']) or (not self.oauth_info['access_token_key']):
            err_msg = 'AccessToken: temporary token data not provided'
            debug_msg(err_msg)
            return (False, err_msg)

        if not self.verifier:
            err_msg = 'AccessToken: verifier not provided'
            debug_msg(err_msg)
            return (False, err_msg)

        try:
            req = urllib2.Request(self.REQ_URL_ACCESS_TOKEN, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            content = response.read()

        except Exception as exc:
            err_msg = str(exc)
            try:
                err_msg += ', ' + str(exc.reason)
            except:
                pass
            err_msg = 'AccessToken: can not get access token: ' + err_msg
            debug_msg(err_msg)
            return (False, err_msg)

        #'oauth_token=AUTHORIZED_OAUTH_TOKEN&oauth_token_secret=AUTHORIZED_OAUTH_TOKEN_SECRET&user_id=ID_OF_USER&screen_name=SCREEN_NAME_OF_USER'
        debug_msg('AccessToken: got access token content: ' + str(content))

        try:
            parsed_content = urllib2.urlparse.parse_qs(content)
        except:
            err_msg = 'AccessToken: can not parse the received request token'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content) is not dict):
            err_msg = 'AccessToken: the received request token is incorrect'
            debug_msg(err_msg)
            return (False, err_msg)

        required_parts = ['oauth_token', 'oauth_token_secret', 'user_id', 'screen_name']
        for one_part in required_parts:
            if (one_part not in parsed_content) or (not parsed_content):
                err_msg = 'AccessToken: the received request token is incomplete, missing: ' + str(one_part)
                debug_msg(err_msg)
                return (False, err_msg)

        oauth_token_key = None
        oauth_token_secret = None
        oauth_user_id = None
        oauth_screen_name = None

        #for pin/verifier, ask at
        #https://api.twitter.com/oauth/authorize?oauth_token=TMP_OAUTH_TOKEN
        pin_url = None

        if (type(parsed_content['oauth_token']) in (list, tuple)) and parsed_content['oauth_token']:
            for part in parsed_content['oauth_token']:
                if part:
                    oauth_token_key = part
                    break
        if not oauth_token_key:
            err_msg = 'AccessToken: the received request is without oauth_token'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content['oauth_token_secret']) in (list, tuple)) and parsed_content['oauth_token_secret']:
            for part in parsed_content['oauth_token_secret']:
                if part:
                    oauth_token_secret = part
                    break
        if not oauth_token_secret:
            err_msg = 'AccessToken: the received request is without oauth_token_secret'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content['user_id']) in (list, tuple)) and parsed_content['user_id']:
            for part in parsed_content['user_id']:
                if part:
                    oauth_user_id = part
                    break
        if not oauth_user_id:
            err_msg = 'AccessToken: the received request is without user_id'
            debug_msg(err_msg)
            return (False, err_msg)

        if (type(parsed_content['screen_name']) in (list, tuple)) and parsed_content['screen_name']:
            for part in parsed_content['screen_name']:
                if part:
                    oauth_screen_name = part
                    break
        if not oauth_screen_name:
            err_msg = 'AccessToken: the received request is without screen_name'
            debug_msg(err_msg)
            return (False, err_msg)

        result_data = {
            'oauth_token_key': str(oauth_token_key),
            'oauth_token_secret': str(oauth_token_secret),
            'user_id': str(oauth_user_id),
            'screen_name': str(oauth_screen_name),
        }

        debug_msg('AccessToken: result data: ' + json.dumps(result_data))

        return (True, result_data)

class SendTweet(object):

    #tweet_params = {
    #    'status': 'the tweet message itself',
    #    'in_reply_to_status_id': 'id of tweet if this is a reply to that tweet; status has to contain @orig_user then',
    #}

    #oauth_info = {
    #    'consumer_key': 'the_app_consumer_key',
    #    'consumer_secret': 'the_app_consumer_secret',
    #    'access_token_key': 'the_authorized_oauth_token',
    #    'access_token_secret': 'the_authorized_oauth_token_secret',
    #}

    REQ_URL_SEND_TWEET = 'https://api.twitter.com/1.1/statuses/update.json'

    tweet_keys = ['status', 'in_reply_to_status_id', 'possibly_sensitive', 'lat', 'long', 'place_id', 'display_coordinates']

    def __init__(self, oauth_info, request_params):
        self.oauth_info = oauth_info
        self.request_params = request_params
        self.tweet_params = {}

        for key in self.tweet_keys:
            if (key in request_params) and (request_params[key]):
                self.tweet_params[key] = str(request_params[key])

    def get_req_params(self):
        return urllib.urlencode(self.tweet_params)

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

    def get_send_tweet(self):
        if (not self.oauth_info['consumer_key']) or (not self.oauth_info['consumer_secret']):
            err_msg = 'SendTweet: consumer app data not provided'
            debug_msg(err_msg)
            return (False, err_msg)
        if (not self.oauth_info['access_token_key']) or (not self.oauth_info['access_token_secret']):
            err_msg = 'SendTweet: authorized token data not provided'
            debug_msg(err_msg)
            return (False, err_msg)

        if 'status' not in self.tweet_params:
            err_msg = 'SendTweet: the "status" parameter that carries the message is not provided in tweet data'
            debug_msg(err_msg)
            return (False, err_msg)

        try:
            req = urllib2.Request(self.REQ_URL_SEND_TWEET, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            content = response.read()

        except Exception as exc:
            err_msg = str(exc)
            try:
                err_msg += ', ' + str(exc.reason)
            except:
                pass
            err_msg = 'SendTweet: can not send tweet: ' + err_msg
            debug_msg(err_msg)
            return (False, err_msg)

        #{_standard_tweet_structure_: "id_str":"491186627696680960", ...}
        debug_msg('SendTweet: got sent tweet: ' + str(content))

        try:
            tweet_data = json.loads(content)
        except Exception as exc:
            err_msg = 'SendTweet: can not parse the received tweet data: ' + str(exc)
            debug_msg(err_msg)
            return (False, err_msg)

        if type(tweet_data) is not dict:
            err_msg = 'SendTweet: wrong type of the received tweet data: ' + str(type(tweet_data))
            debug_msg(err_msg)
            return (False, err_msg)

        if 'id_str' not in tweet_data:
            err_msg = 'SendTweet: the received tweet data do not contain "id_str" field'
            debug_msg(err_msg)
            return (False, err_msg)

        return (True, tweet_data)

class RequestProcessor(object):

    def _write_error(self, msg):
        sys.stderr.write(str(msg) + '\n')
        sys.exit(1)

    def _write_json(self, data):
        sys.stdout.write(str(json.dumps(data)) + '\n')
        sys.exit(0)

    def run_pipe(self, run_specs, request_params, oauth_info):

        request_type = run_specs.get_request_type()

        if 'auth_initialize' == request_type:
            negotiator = RequestToken(oauth_info, request_params)
            result = negotiator.get_request_token()
            if result[0]:
                self._write_json(result[1])
            else:
                err_msg = 'RequestProcessor: can not get the request token'
                debug_msg(err_msg)
                err_msg += '; ' + str(result[1])
                self._write_error(err_msg)
            return

        if 'auth_finalize' == request_type:
            negotiator = AccessToken(oauth_info, request_params)
            result = negotiator.get_access_token()
            if result[0]:
                self._write_json(result[1])
            else:
                err_msg = 'RequestProcessor: can not get the access token'
                debug_msg(err_msg)
                err_msg += '; ' + str(result[1])
                self._write_error(err_msg)
            return

        if 'send_tweet' == request_type:
            save_url = run_specs.get_save_url()
            if not save_url:
                err_msg = 'RequestProcessor: no save_url was provided for the tweet to be sent'
                debug_msg(err_msg)
                self._write_error(err_msg)
                return

            if ('endpoint_id' not in request_params) or (not request_params['endpoint_id']):
                err_msg = 'RequestProcessor: endpoint_id was not provided for the tweet to be sent'
                debug_msg(err_msg)
                self._write_error(err_msg)
                return

            if ('filter' not in request_params) or (not request_params['filter']):
                err_msg = 'RequestProcessor: filter (carrying sort info) was not provided for the tweet to be sent'
                debug_msg(err_msg)
                self._write_error(err_msg)
                return

            sender = SendTweet(oauth_info, request_params)
            result_tweet = sender.get_send_tweet()
            if not result_tweet[0]:
                err_msg = 'RequestProcessor: can not send the tweet'
                debug_msg(err_msg)
                err_msg += '; ' + result_tweet[1]
                self._write_error(err_msg)
                return

            result_tweet_part = result_tweet[1]
            result_data = {
                'tweet': result_tweet_part,
                'endpoint': {'endpoint_id': request_params['endpoint_id']},
                'filter': request_params['filter'],
            }

            if ('in_reply_to_status_id' in request_params) and request_params['in_reply_to_status_id']:
                result_data['type'] = 'reply'
            else:
                result_data['type'] = 'announce'

            for key_other in ['request']:
                if (key_other in request_params) and request_params[key_other]:
                    result_data[key_other] = request_params[key_other]

            tweet_id = result_tweet_part['id_str']
            use_url = save_url
            if not use_url.endswith('/'):
                use_url += '/'
            try:
                use_url += str(tweet_id)
            except:
                err_msg = 'RequestProcessor: damaged tweet data of the sent tweet'
                debug_msg(err_msg)
                self._write_error(err_msg)
                return

            elsd = ElsDepositor(request_type, use_url)
            result = elsd.save_result_data(result_data)
            if not result[0]:
                err_msg = 'RequestProcessor: error during tweet-saving processing'
                debug_msg(err_msg)
                err_msg += '; ' + str(result[1])
                self._write_error(err_msg)
                return

            self._write_json({'id_str': tweet_id})
            return

        err_msg = 'RequestProcessor, unknown request type'
        debug_msg(err_msg)
        self._write_error(err_msg)
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
            one_line = sys.stdin.readline()
            if not one_line:
                break
            twitter_param_list.append(one_line)
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

            if not part in oauth_set:
                if is_required:
                    is_correct = False
                    break
                continue
            if not oauth_set[part]:
                if is_required:
                    is_correct = False
                    break
                continue
            try:
                one_oauth_use[part] = str(oauth_set[part])
            except:
                if is_required:
                    is_correct = False
                    break
                continue
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
    else:
        err_msg = 'wrong data supplied'
        sys.stderr.write(str(err_msg) + '\n')
        sys.exit(1)
