#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
import os
import random
import sys
import requests
import json 

import re 

from urllib.parse import urlparse
from contextlib import closing

hostname = 'en.wikipedia.org'

base_url_regex = '^http.?:\/\/.+.\..+?(\/.+)'


def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

def set_header():  
    # Now this is where I inject
    headers = {
        'Host': hostname
    }

    return headers

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)

    def do_GET(self, body=True):
        sent = False
        try:

            url = 'http://{}{}'.format(hostname, self.path)
            req_header : dict = self.parse_headers()

            # print(req_header)
            # print(url)

            query = urlparse(self.path).query

            if ( '/playlist/' in self.path ): 
                # Rewrite URLs
                print('Rewriting playlist')
                self.send_response(200)
                self.wfile.write( 'Placeholder'.encode(encoding='UTF-8') )
                sent = True 
                return
                 


            resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False, stream=True)
            
            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            if body:
                for chunk in resp.iter_content(4096):
                    self.wfile.write(chunk)
            sent = True    
            return

        finally:
            # self.finish()
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def do_POST(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            content_len = int(self.headers.getheader('content-length', 0))
            post_body = self.rfile.read(content_len)
            req_header = self.parse_headers()

            resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            if body:
                self.wfile.write(resp.content)
            return
        finally:
            self.finish()
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def parse_headers(self):
        toReturn = {}
        for header in self.headers._headers:
            toReturn[header[0]] = header[1]

        return toReturn 

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        # print('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                print(key, respheaders[key])
                # self.send_header(key, respheaders[key])
        if 'content-length' in resp.headers.keys():
            self.send_header('Content-Length', resp.headers['content-length'])
        
        self.end_headers()



def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=9999,
                        help='serve HTTP requests on specified port (default: random)')
    args = parser.parse_args(argv)
    return args

def main(argv=sys.argv[1:]):
    args = parse_args(argv)
    print('http server is starting on port {}...'.format(args.port))
    server_address = ('127.0.0.1', args.port)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()