#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copy the file into 'stw_feed.py' and fill in the stream constraints
https://dev.twitter.com/docs/streaming-apis/parameters

stream_filter['track'] = 'term1,term2,...,termN'
stream_filter['locations'] = '-122.75,36.8,-121.75,37.8,-74,40,-73,41'

Notice that Twitter takes those parameters in "OR" way,
i.e. received tweets have at least one constraint satisfied,
but they do not need meet all the specificed constraints.
'''

stream_filter = {}
