#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2
from pymongo import MongoClient
from newst_auth import oauth_info
from newst_feed import stream_filter

def insert_data():
    client = MongoClient()
    db = client['citizendesk']

    coll = db['newstwister_oauths']
    coll.save({'_id':1, 'spec': oauth_info})

    coll = db['newstwister_filters']
    coll.save({'_id':1, 'spec': stream_filter})

if __name__ == '__main__':
    insert_data()

