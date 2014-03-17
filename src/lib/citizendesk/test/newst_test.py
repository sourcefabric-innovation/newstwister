#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2
from collections import namedtuple
from pymongo import MongoClient

MONGODB_SERVER_HOST = 'localhost'
MONGODB_SERVER_PORT = 27017
DBNAME = 'citizendesk'
NEWSTWISTER_URL = 'http://localhost:9054/'
ENDPOINT_ID = 3
OAUTH_ID = 1
FILTER_ID = 1

class MongoDBs(object):
    def __init__(self, dbname=''):
        self.dbname = dbname
        self.db = None

    def set_dbname(self, dbname):
        self.dbname = dbname

    def get_dbname(self):
        return self.dbname

    def set_db(self, db):
        self.db = db

    def get_db(self):
        return self.db

def setup_db(server, port, dbname):
    mongo_dbs = MongoDBs()
    mongo_dbs.set_dbname(dbname)
    DbHolder = namedtuple('DbHolder', 'db')
    mongo_dbs.set_db(DbHolder(db=MongoClient(server, port)[mongo_dbs.get_dbname()]))
    return mongo_dbs

def run_test():
    file_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(os.path.dirname(os.path.dirname(file_dir)))
    from citizendesk.external.feeds.twt.newstwisterc import NewstwisterStorage, NewstwisterConnector

    storage = NewstwisterStorage(setup_db(MONGODB_SERVER_HOST, MONGODB_SERVER_PORT, DBNAME).get_db().db)
    connector = NewstwisterConnector(NEWSTWISTER_URL)

    res = connector.request_start(storage, ENDPOINT_ID, OAUTH_ID, FILTER_ID)
    print(res)
    if res is not None:
        return

    res = connector.request_status(storage, OAUTH_ID)
    print(res)

    res = connector.request_stop(storage, OAUTH_ID)
    print(res)

if __name__ == '__main__':
    run_test()


