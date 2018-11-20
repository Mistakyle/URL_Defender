import urlscan
import vt

def performScan(url):
    score = 0
    score += vt.vt_urlscan(url) # this line causes an error in vt.py

    score += urlscan.urlscan(url)

    return score;
