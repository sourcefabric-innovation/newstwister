#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2

try:
    from slots_auth import oauth_info
except:
    print('the "slots_auth.py" file should contain the API keys for Twitter streams')
    sys.exit(1)

BASE_URL = 'http://localhost:9060'

def send_data():
    save_url = BASE_URL
    if not save_url.endswith('/'):
        save_url += '/'
    save_url += 'feeds/twt/oauth/'

    for auth_set in oauth_info:
        params = {}
        params['spec'] = auth_set

        save_status = None
        try:
            post_data = json.dumps(params)
            req = urllib2.Request(save_url, post_data, {'Content-Type': 'application/json'})
            response = urllib2.urlopen(req)
            save_result = response.read()
            save_status = json.loads(save_result)
        except Exception as exc:
            print('error during sending the oauth data: ' + str(exc))
            save_status = None

        print(save_status)

if __name__ == '__main__':
    send_data()


