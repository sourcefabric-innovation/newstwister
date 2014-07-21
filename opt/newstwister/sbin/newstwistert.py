#!/usr/bin/env python

import sys, os, time, json, argparse
import logging, logging.handlers
import urllib, urllib2, select
import oauth2 as oauth
import signal, atexit
import ctypes

class RequestToken():

    oauth_info = {
        'consumer_key': 'BBAm7CgCAfXfniYvMZ1scA',
        'consumer_secret': 'X0zyTjJYNvvNGgAN3r8fIkqikynWowVRHMFAM5OqkOo',
        'access_token_key': '',
        'access_token_secret': '',
    }

    REQ_URL_REQUEST_TOKEN = 'https://api.twitter.com/oauth/request_token'

    def ask_token(self):
        request_token_url = self.REQ_URL_REQUEST_TOKEN + '?oauth_callback=oob&x_auth_access_type=write'

        consumer = oauth.Consumer(key=self.oauth_info['consumer_key'],secret=self.oauth_info['consumer_secret'])
        client = oauth.Client(consumer)
        try:
            resp, content = client.request(request_token_url, 'GET')
        except exc:
            return None

        #oauth_token=DGgTOFyreYwPxvA1oj7v0L53bOH57cqhrenI216e34&oauth_token_secret=NablgajRrCTdttzqvuaa5B62V5CKXXbxlr5U9Y55g&oauth_callback_confirmed=true
        print(content)

        return content

        #for pin/verifier, ask at
        #https://api.twitter.com/oauth/authorize?oauth_token=DGgTOFyreYwPxvA1oj7v0L53bOH57cqhrenI216e34

class AccessToken():

    verifier = '4831749'

    oauth_info = {
        'consumer_key': 'BBAm7CgCAfXfniYvMZ1scA',
        'consumer_secret': 'X0zyTjJYNvvNGgAN3r8fIkqikynWowVRHMFAM5OqkOo',
        'access_token_key': 'DGgTOFyreYwPxvA1oj7v0L53bOH57cqhrenI216e34',
        'access_token_secret': 'NablgajRrCTdttzqvuaa5B62V5CKXXbxlr5U9Y55g',
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

        #for key in conn_headers:
        #    conn_headers[key] = [conn_headers[key]]

        return conn_headers

    def make_req(self):

        try:
            req = urllib2.Request(self.REQ_URL_ACCESS_TOKEN, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            req_result = response.read()

            #'oauth_token=1960324645-EogUITWwBLzW0MwbAfb54mODfGvD8pAPT2mkXnE&oauth_token_secret=Vcgsm9iZmmqK6NROhg7XPN4RiqPAMeUupRIy4VHKqLvUo&user_id=1960324645&screen_name=cdeskdev'
            print('req_result: ' + str(req_result))

        except Exception as exc:
            print('exception: ' + str(exc))
            print('exception: ' + str(exc.reason))
            pass


class SendTweet():

    oauth_info = {
        'consumer_key': 'BBAm7CgCAfXfniYvMZ1scA',
        'consumer_secret': 'X0zyTjJYNvvNGgAN3r8fIkqikynWowVRHMFAM5OqkOo',
        'access_token_key': '1960324645-EogUITWwBLzW0MwbAfb54mODfGvD8pAPT2mkXnE',
        'access_token_secret': 'Vcgsm9iZmmqK6NROhg7XPN4RiqPAMeUupRIy4VHKqLvUo',
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

        #for key in conn_headers:
        #    conn_headers[key] = [conn_headers[key]]

        return conn_headers

    def make_req(self):

        try:
            req = urllib2.Request(self.REQ_URL_SEND_TWEET, self.get_req_params(), self.get_headers())
            response = urllib2.urlopen(req)
            req_result = response.read()

            #{"created_at":"Mon Jul 21 11:43:12 +0000 2014","id":491186627696680960,"id_str":"491186627696680960","text":"sent from a python","source":"\u003ca href=\"http:\/\/www.sourcefabric.org\/\" rel=\"nofollow\"\u003ecdeskdev-001\u003c\/a\u003e","truncated":false,"in_reply_to_status_id":null,"in_reply_to_status_id_str":null,"in_reply_to_user_id":null,"in_reply_to_user_id_str":null,"in_reply_to_screen_name":null,"user":{"id":1960324645,"id_str":"1960324645","name":"CDesk dev","screen_name":"cdeskdev","location":"","description":"","url":null,"entities":{"description":{"urls":[]}},"protected":false,"followers_count":0,"friends_count":0,"listed_count":0,"created_at":"Mon Oct 14 09:01:46 +0000 2013","favourites_count":0,"utc_offset":null,"time_zone":null,"geo_enabled":false,"verified":false,"statuses_count":4,"lang":"en","contributors_enabled":false,"is_translator":false,"is_translation_enabled":false,"profile_background_color":"C0DEED","profile_background_image_url":"http:\/\/abs.twimg.com\/images\/themes\/theme1\/bg.png","profile_background_image_url_https":"https:\/\/abs.twimg.com\/images\/themes\/theme1\/bg.png","profile_background_tile":false,"profile_image_url":"http:\/\/abs.twimg.com\/sticky\/default_profile_images\/default_profile_6_normal.png","profile_image_url_https":"https:\/\/abs.twimg.com\/sticky\/default_profile_images\/default_profile_6_normal.png","profile_link_color":"0084B4","profile_sidebar_border_color":"C0DEED","profile_sidebar_fill_color":"DDEEF6","profile_text_color":"333333","profile_use_background_image":true,"default_profile":true,"default_profile_image":true,"following":false,"follow_request_sent":false,"notifications":false},"geo":null,"coordinates":null,"place":null,"contributors":null,"retweet_count":0,"favorite_count":0,"entities":{"hashtags":[],"symbols":[],"urls":[],"user_mentions":[]},"favorited":false,"retweeted":false,"lang":"cy"}
            #{"created_at":"Mon Jul 21 11:48:59 +0000 2014","id":491188081480175617,"id_str":"491188081480175617","text":"@cdeskdev it must have been a long one, i would guess","source":"\u003ca href=\"http:\/\/www.sourcefabric.org\/\" rel=\"nofollow\"\u003ecdeskdev-001\u003c\/a\u003e","truncated":false,"in_reply_to_status_id":491186627696680960,"in_reply_to_status_id_str":"491186627696680960","in_reply_to_user_id":1960324645,"in_reply_to_user_id_str":"1960324645","in_reply_to_screen_name":"cdeskdev","user":{"id":1960324645,"id_str":"1960324645","name":"CDesk dev","screen_name":"cdeskdev","location":"","description":"","url":null,"entities":{"description":{"urls":[]}},"protected":false,"followers_count":0,"friends_count":0,"listed_count":0,"created_at":"Mon Oct 14 09:01:46 +0000 2013","favourites_count":0,"utc_offset":null,"time_zone":null,"geo_enabled":false,"verified":false,"statuses_count":5,"lang":"en","contributors_enabled":false,"is_translator":false,"is_translation_enabled":false,"profile_background_color":"C0DEED","profile_background_image_url":"http:\/\/abs.twimg.com\/images\/themes\/theme1\/bg.png","profile_background_image_url_https":"https:\/\/abs.twimg.com\/images\/themes\/theme1\/bg.png","profile_background_tile":false,"profile_image_url":"http:\/\/abs.twimg.com\/sticky\/default_profile_images\/default_profile_6_normal.png","profile_image_url_https":"https:\/\/abs.twimg.com\/sticky\/default_profile_images\/default_profile_6_normal.png","profile_link_color":"0084B4","profile_sidebar_border_color":"C0DEED","profile_sidebar_fill_color":"DDEEF6","profile_text_color":"333333","profile_use_background_image":true,"default_profile":true,"default_profile_image":true,"following":false,"follow_request_sent":false,"notifications":false},"geo":null,"coordinates":null,"place":null,"contributors":null,"retweet_count":0,"favorite_count":0,"entities":{"hashtags":[],"symbols":[],"urls":[],"user_mentions":[{"screen_name":"cdeskdev","name":"CDesk dev","id":1960324645,"id_str":"1960324645","indices":[0,9]}]},"favorited":false,"retweeted":false,"lang":"en"}
            print('req_result: ' + str(req_result))

        except Exception as exc:
            print('exception: ' + str(exc))
            print('exception: ' + str(exc.reason))
            pass





