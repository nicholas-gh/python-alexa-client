#!/usr/bin/env python
import requests
import logging
import json
import urllib.parse
import webbrowser
import http.server
#import multipart
import re
import cgi
import io
import pprint
from _thread import start_new_thread
import datetime
import sys

import gi
gi.require_version('Gst', '1.0')
from gi.repository import GObject, Gst

import gio

GObject.threads_init()
Gst.init(None)

if False:
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


CLIENT_ID = 'FILLMEIN'
CLIENT_SECRET = 'FILLMEIN'

payload = {'scope': 'alexa:all',
           'scope_data': json.dumps({
               "alexa:all": {
                   "productID": "FILLMEIN",
                   "productInstanceAttributes": {
                       "deviceSerialNumber": "FILLMEIN"
                   }
               }
           }),
           'client_id': CLIENT_ID,
           'response_type': 'code',
           'redirect_uri': 'http://localhost:3000/authresponse',
           }

#r = requests.get("https://www.amazon.com/ap/oa", params=payload)
#print r.text

class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        args = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        print(args)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Thanks")
        
        payload = {'client_id': CLIENT_ID,
                   'client_secret': CLIENT_SECRET,
                   'grant_type': 'authorization_code',
                   'code': args['code'][0],
                   'redirect_uri': 'http://localhost:3000/authresponse',                   
        }
        
        r = requests.post("https://api.amazon.com/auth/o2/token", data=payload)
        tokens = r.json()
        #print(tokens)
        payload.update(tokens)
        date_format = "%a %b %d %H:%M:%S %Y"
        expiry_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=tokens['expires_in'])
        payload['expiry'] = expiry_time.strftime(date_format)

        open("tokens.json",'w').write(json.dumps(payload))
        
def run(server_class=http.server.HTTPServer, handler_class=HTTPRequestHandler):
    server_address = ('', 3000)
    httpd = server_class(server_address, handler_class)
    httpd.handle_request()

webbrowser.open("{}?{}".format("https://www.amazon.com/ap/oa",urllib.parse.urlencode(payload)))
run()
