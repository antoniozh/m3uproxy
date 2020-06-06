#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
import os
import random
import sys
import requests
import json 

import re 

from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from contextlib import closing

playlists : dict = None 
load_balancing = {}

base_url_regex = '^http.?:\/\/.+.\..+?(\/.+)'


def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)

    def do_GET(self, body=True):
        sent = False
        try:
            req_header : dict = self.parse_headers()

            # print(req_header)
            # print(url)

            parse = urlparse(self.path)

            query = parse_qs( parse.query  )
             
            if ( 'get_playlist' in query.keys() ): 
                
                # Rewrite URLs
                print('Rewriting playlist')

                # Select URL by playlist query
                provider = list(filter( lambda x : x['name'] == query['get_playlist'][0] , playlists))[0]

                url = provider['playlist_url']

                resp = requests.get(url, headers=merge_two_dicts(req_header, {"Host" : urlparse(url).netloc } ), params=provider['users'][0]['params'] , verify=False)
                
                content = resp.content.decode().split('\n')
                
                for i in range(0, len(content)):
                    line : str = content[i]
                    match : re.Match = re.match(base_url_regex, line)
                    if match != None :
                        line_parsed = urlparse(line)

                        line_query = parse_qs(line_parsed.query)
                        line_query['playlist'] = query['get_playlist'][0]
                        # TODO semicolon must be replaced in a better way
                        built_string = urlunparse( ('http', req_header['Host'], line_parsed.path.replace("\r", ""), urlencode(query=line_query) , None , None  ) )
                        content[i] = built_string.replace(";", "?")

                self.send_response(200)
                self.send_resp_headers(resp)
                self.wfile.write( '\n'.join(content).encode() )
                sent = True 
                return
           
            if ( 'playlist' in query.keys() ):
                provider = list(filter( lambda x : x['name'] == query['playlist'][0] , playlists))[0]

                url = provider['stream_host']

                # TODO: Restream

                # TODO: Make threshold configurable
                user_list =  list(filter(lambda x : "used" not in x.keys() or x["used"] < 1, provider['users']))

                if ( len(user_list) == 0 ): 
                    self.send_error(404, "Out of connections! \n")
                    return

                user = user_list[0]
                user["used"] = 1

                resp = requests.get(url + self.path , headers=merge_two_dicts(req_header, {"Host" : urlparse(url).netloc } ), params=user['params'] , verify=False,  stream=True)

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    for chunk in resp.iter_content(4096):
                        self.wfile.write(chunk)
                sent = True    
                return

            else:
                self.wfile.write('Use query params \n'.encode())
                self.send_response(200)

        except Exception as e:
            print(e)
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

    global playlists 
    playlists = json.load( open('playlists.json', 'r') )

    print('http server is starting on port {}...'.format(args.port))
    server_address = ('0.0.0.0', args.port)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()