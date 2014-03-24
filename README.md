Newstwister
========

Taking tweets from Twitter streams into Elasticsearch

### install

Create application with access token credetials in Twitter.
Fill in the oAuth strings into node/stw_auth.py.
Put some filter constraint into node/stw_feed.py.
Run the node/stw_node.py

The tweets are saved into Elasticsearch database,
into index 'citizen_desk' and 'tweets' type.

### requirements

Python framework Twisted is used for asynchronous processing of the tweets.
Elastic search has to be running on the node computer.

If used under Ubuntu, next packages have to be installed:
python-twisted
python-oauth2
python-setproctitle



