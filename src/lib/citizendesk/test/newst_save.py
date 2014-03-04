#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2
from pymongo import MongoClient
import os, sys, datetime, json, logging
import atexit
from flask import Flask
from flask import request, Blueprint

HOST = 'localhost'
PORT = 9055
DEBUG = False

tweet_plugin = Blueprint('tweet_plugin', __name__)

@tweet_plugin.route('/newstwister/tweets/<tweet_id>', defaults={}, methods=['POST'], strict_slashes=False)
def tweet_post(tweet_id):
    print('tweet post: ' + str(tweet_id))
    print(request.args)
    print(request.get_json(True, False, False))
    return (json.dumps({'_message': 'tweet saved'}), 200, {'Content-Type': 'application/json'})

app = Flask(__name__)
app.register_blueprint(tweet_plugin)

@app.errorhandler(404)
def page_not_found(error):
    request_url = str(request.url)
    logging.warning('page not found: ' + request_url)
    return (json.dumps({'_message': 'page not found'}), 404, {'Content-Type': 'application/json'})

def run_flask(host, port, debug):
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_flask(HOST, PORT, DEBUG)


