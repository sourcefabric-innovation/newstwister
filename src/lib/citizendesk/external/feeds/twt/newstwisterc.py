#!/usr/bin/env python

import os, sys, datetime, json, logging
import urllib, urllib2
import copy

NODE_NONE = 0
NODE_INIT = 1
NODE_RUNS = 2

COLLECTION_OAUTHS = 'twt_oauths'
COLLECTION_FILTERS = 'twt_filters'
COLLECTION_STATUSES = 'twt_streams'

class NewstwisterStorage():
    def __init__(self, db=None):
        self.db = db

    def get_oauth_spec(self, oauth_id):
        spec = None
        try:
            collection = self.db[COLLECTION_OAUTHS]
            doc = collection.find_one({'_id': oauth_id})
            spec = doc['spec']
        except:
            spec = None
        return spec

    def get_filter_spec(self, filter_id):
        spec = None
        try:
            collection = self.db[COLLECTION_FILTERS]
            doc = collection.find_one({'_id': filter_id})
            spec = {}
            for key in doc['spec']:
                if doc['spec'][key]:
                    spec[key] = doc['spec'][key]
        except:
            spec = None
        return spec

    def get_stream_status(self, status_id):
        stage = None
        try:
            collection = self.db[COLLECTION_STATUSES]
            stage = collection.find_one({'_id': status_id})
        except:
            stage = None
        if stage:
            stage['oauth_id'] = stage['_id']
            del(stage['_id'])
        return stage

    def set_stream_status(self, stream_stage):
        stream_stage = copy.deepcopy(stream_stage)
        if 'oauth_id' not in stream_stage:
            return False
        if 'oauth_id' in stream_stage:
            stream_stage['_id'] = stream_stage['oauth_id']
            del(stream_stage['oauth_id'])
        try:
            collection = self.db[COLLECTION_STATUSES]
            collection.save(stream_stage)
        except:
            return False
        return True

class NewstwisterConnector():
    def __init__(self, base_url):
        self.ctrl_base_url = base_url

    def request_start(self, storage, endpoint_id, oauth_id, filter_id):
        # read auth_spec from db
        # read filter_spec from db
        # check if stream is available
        # make connection to twister_main
        # take response from connection
        # save response into db

        start_url = self.ctrl_base_url
        if not start_url.endswith('/'):
            start_url += '/'
        start_url += '_start'

        oauth_params = storage.get_oauth_spec(oauth_id)
        filter_params = storage.get_filter_spec(filter_id)

        stream_spec = {'oauth_id': oauth_id}
        stream_status = storage.get_stream_status(oauth_id)
        if stream_status and ('stage' in stream_status) and (stream_status['stage'] != NODE_NONE):
            return None

        stream_spec['filter_id'] = filter_id
        stream_spec['stage'] = NODE_INIT
        storage.set_stream_status(stream_spec)

        params = {}
        params['oauth_info'] = oauth_params
        params['stream_filter'] = filter_params
        params['endpoint'] = {'endpoint_id': endpoint_id}

        node_status = None
        try:
            post_data = json.dumps(params)
            req = urllib2.Request(start_url, post_data, {'Content-Type': 'application/json'})
            response = urllib2.urlopen(req)
            node_result = response.read()
            node_status = json.loads(node_result)
            if type(node_status) is not dict:
                node_status = None
        except Exception as exc:
            #print(exc.read())
            node_status = None

        node_runs = None
        if node_status and ('node' in node_status):
            stream_spec['node_id'] = node_status['node']
            if ('status' in node_status) and node_status['status']:
                stream_spec['stage'] = NODE_RUNS
                node_runs = True
            else:
                stream_spec['stage'] = NODE_NONE
                node_runs = False
            storage.set_stream_status(stream_spec)
        else:
            stream_spec['stage'] = NODE_NONE
            storage.set_stream_status(stream_spec)

        return node_runs

    def request_stop(self, storage, oauth_id):
        stop_url = self.ctrl_base_url
        if not stop_url.endswith('/'):
            statop_url += '/'
        stop_url += '_stop'

        stream_spec = {'oauth_id': oauth_id}

        stream_status = storage.get_stream_status(oauth_id)
        if (not stream_status) or ('stage' not in stream_status) or (stream_status['stage'] != NODE_RUNS):
            return None
        if ('node_id' not in stream_status) or (not stream_status['node_id']):
            return None

        params = {}
        params['node'] = str(stream_status['node_id'])

        node_status = None
        try:
            for param_key in params:
                params[param_key] = params[param_key].encode('utf8')

            post_data = urllib.urlencode(params)
            req = urllib2.Request(stop_url, post_data)
            response = urllib2.urlopen(req)
            node_result = response.read()
            node_status = json.loads(node_result)
            if type(node_status) is not dict:
                node_status = None
        except Exception as exc:
            #print(exc)
            node_status = None

        if (not node_status) or ('node' not in node_status) or ('status' not in node_status):
            return None

        node_stopped = False
        if not node_status['status']:
            stream_spec['stage'] = NODE_NONE
            storage.set_stream_status(stream_spec)
            node_stopped = True

        return node_stopped

    def request_status(self, storage, oauth_id):
        status_url = self.ctrl_base_url
        if not status_url.endswith('/'):
            status_url += '/'
        status_url += '_status'

        stream_spec = {'oauth_id': oauth_id}
        stream_status = storage.get_stream_status(oauth_id)
        if (not stream_status) or ('stage' not in stream_status) or (stream_status['stage'] != NODE_RUNS):
            return None
        if ('node_id' not in stream_status) or (not stream_status['node_id']):
            return None

        try:
            status_url += '?node=' + str(int(stream_status['node_id']))
        except:
            return None

        try:
            response = urllib2.urlopen(status_url)
            node_result = response.read()
            node_status = json.loads(node_result)
            if type(node_status) is not dict:
                node_status = None
        except Exception as exc:
            #print(exc)
            return None

        if (not node_status) or ('node' not in node_status) or ('status' not in node_status):
            return None

        return node_status['status']

