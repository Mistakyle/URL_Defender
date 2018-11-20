import requests
import json
import config

api_key=config.url_key
purl = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
params = {'key': api_key}

#TODO: regex to make sure it is a valid url or else this service will break :O
def urlscan(url):
    payload = {'client': {'clientId': "url-defender", 'clientVersion': "0.1"},
            'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE"],
                           'platformTypes': ["ANY_PLATFORM"],
                           'threatEntryTypes': ["URL"],
                           'threatEntries': [{'url': url}]}}

    r = requests.post(purl, params=params, json=payload).json()

    # Print response
    # evaluates to true if the list is not empty which will only be in the case
    # of a threat found.
    if r:
        return 1;
    return 0;
