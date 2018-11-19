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
        test = vt.get_url_report(url, response["results"]["scan_id"])
        virustotal.insert({'url': url,'date': test["results"]["scan_date"], 'positives': test["results"]["positives"]})
        return test["results"]["positives"]


    return report["positives"]


def getFileReport(url):
    report = virustotal.find_one({'url': url})

    if report is None:
        return False

    return report
