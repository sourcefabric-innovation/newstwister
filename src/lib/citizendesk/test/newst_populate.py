#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2
from pymongo import MongoClient
from newst_auth import oauth_info
from newst_feed import stream_filter

def insert_data():
    client = MongoClient()
    db = client['citizendesk']

    doc_oauth = {
        'consumer_key': None,
        'consumer_secret': None,
        'access_token_key': None,
        'access_token_secret': None
    }
    for key in doc_oauth:
        if (key in oauth_info) and oauth_info[key]:
            doc_oauth[key] = oauth_info[key]

    coll = db['twt_oauths']
    coll.save({'_id':1, 'spec': doc_oauth})

    doc_filter = {
        'follow': [],
        'track': [],
        'locations': [],
        'language': None
    }
    for key in doc_filter:
        if (key in stream_filter) and stream_filter[key]:
            doc_filter[key] = stream_filter[key]

    coll = db['twt_filters']
    coll.save({'_id':1, 'spec': doc_filter})

if __name__ == '__main__':
    insert_data()

