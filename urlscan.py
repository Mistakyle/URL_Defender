import requests
import json
import config
from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo

app = Flask(__name__)
mongo = config.connect(app)
urlscans = mongo.db.urlscans

api_key=config.url_key
purl = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
params = {'key': api_key}

#TODO: regex to make sure it is a valid url or else this service will break :O
def urlscan(url):

    result = getScanResults(url)

    if result == False:
        payload = {'client': {'clientId': "url-defender", 'clientVersion': "0.1"},
                'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE"],
                               'platformTypes': ["ANY_PLATFORM"],
                               'threatEntryTypes': ["URL"],
                               'threatEntries': [{'url': url}]}}

        result = requests.post(purl, params=params, json=payload).json()

        # TODO add date maybe
        urlscans.insert({'url': url, 'result': result})

        # Print response
        # evaluates to true if the list is not empty which will only be in the case
        # of a threat found.

    if result:
        return 1

    return 0;

def getScanResults(url):
    result = urlscans.find_one({'url':url})

    if result is None:
        return False

    return result
