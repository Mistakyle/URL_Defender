from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo
import config

app = Flask(__name__)
API_KEY = config.API_KEY
vt = VirusTotalPublicApi(API_KEY)
mongo = config.connect(app)

virustotal = mongo.db.virustotal


#TODO: Check date and make sure the report stored in mongo is current
def vt_urlscan(url):

    report = getFileReport(url)

    if report == False:
        response = vt.scan_url(url)
        #TODO: WILL GET AN ERROR IF THE URL REPORT DOES NOT EXIST, IF SO MUST CREATE ONE FIRST
        # but we are running a scan, maybe look into how long it takes for the scan to update
        # it seems that its not using the scan because the last scan was not the day we are calling it

        # all of this is irrelevant if the data is in the virustotal collection
        test = vt.get_url_report(url, response["results"]["scan_id"])
        print(test)
        virustotal.insert({'url': url,'date': test["results"]["scan_date"], 'positives': test["results"]["positives"]})
        if test["results"]["positives"] is not 0:
            return 1
        return 0

    # at least one virus found

    if report["positives"] != 0:
        return 1;

    return 0 # no viruses found


def getFileReport(url):
    report = virustotal.find_one({'url': url})

    if report is None:
        return False

    return report
