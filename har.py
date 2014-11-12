#!/usr/bin/env python
"""
Author: Vikas Gupta vikasgupta.nit@gmail.com
Date: 12 November 2014

Original script from https://gist.github.com/rouli/5476544, updated it for mitmproxy v0.11
"""

#To use keep libmproxy in the same folder as this script

import binascii, sys, json
import version, tnetstring
from libmproxy import flow
from libmproxy.protocol import primitives, http
from datetime import datetime
import time

class Flow:
    """
    Object containing request, response, client_conn and server_conn state objects
    """
    def __init__(self,request, response, client_conn, server_conn):
        self.request = request
        self.response = response
        self.client_conn = client_conn
        self.server_conn = server_conn

def create_har(flows):
    return {
        "log":{
            "version": "1.2",
            "comment": "exported @ " + time.strftime("%m/%d/%Y %I:%M:%S %p"),
            "creator": {"name":"mitmproxy","version":"0.1","comment":"Contact vikasgupta.nit@gmail.com"},
            "entries": [format_flow(flows)]
        }
    }

def format_flow(fl):
    result = {
        "startedDateTime":format_timestamp(fl),
        "time":flow_total_duration(fl),
        "request":format_request(request),
        "response":format_response(response),
        "cache":{}, # mitmproxy is not cache-aware
        "timings":format_flow_timings(fl),
        "connection":client_conn.address.port
    }
    return result

def format_request(request):
    result = {
        'method':request.method,
        'url':request.scheme + request.host + request.path,
        'httpVersion':"HTTP/%d.%d"%request.httpversion,
        'cookies':format_request_cookies(request.get_cookies()),
        'headers':format_headers(request.headers),
        'queryString':format_query_parameters(request.get_query()),
        'headersSize':len(request.headers),
    }

    if request.content:
        result['postData'] = format_request_data(request)
        result['bodySize'] = len(request.content)
    else:
        result['bodySize'] = -1

    return result

def format_response(response):
    result = {
        'status':response.code,
        'statusText':response.msg,
        'httpVersion':"HTTP/%d.%d"%(response.httpversion[0],response.httpversion[1]),
        'cookies':format_response_cookies(response.get_cookies()),
        'headers':format_headers(response.headers),
        'content':format_response_data(response),
        'redirectURL':format_redirect_url(response),
        'headersSize':len(response.headers),
        'bodySize':len(response.content),
    }
    return result

def format_timestamp(fl):
    # currently we don't keep the dns or tcp timings, so the earliest
    # timestamps for us to use is the request send time.
    timestamp = fl.request.timestamp_start
    return datetime.utcfromtimestamp(timestamp).isoformat()+'+00:00'

def round_timestamp(ts):
    return int(ts*1000)

def flow_total_duration(fl):
    # TODO: what without response, can a HAR file be created?
    return round_timestamp(fl.response.timestamp_end)-round_timestamp(fl.request.timestamp_start)

def format_flow_timings(fl):
    return {
        # event though the documentation says we should not add 'blocked','dns' and 'connect',
        # the online viewer will not without those
        'blocked':-1,
        'dns':-1,
        'connect':-1,
        'send':round_timestamp(fl.request.timestamp_end)-round_timestamp(fl.request.timestamp_start),
        'wait':round_timestamp(fl.response.timestamp_start)-round_timestamp(fl.request.timestamp_end),
        'receive':round_timestamp(fl.response.timestamp_end)-round_timestamp(fl.response.timestamp_start),
    }


def format_headers(headers):
    if not headers:
        return []
    return [{"name":key, "value":value} for key, value in headers.items()]

def format_query_parameters(query_parameters):
    if not query_parameters:
        return []
    return [{"name":key, "value":value} for key, value in query_parameters.items()]

def format_request_cookies(cookies):
    if not cookies:
        return []
    return [{"name":key, "value":value} for key, (value, parameters) in cookies.items()]

def format_response_cookies(cookies):
    if not cookies:
        return []
    result = []
    for key, (value, parameters) in cookies.items():
        cookie = {"name":key, "value":value}
        for param in ("path", "domain", "expires"):
            if param in parameters:
                cookie[param] = parameters[param]
        if "httponly" in parameters:
            cookie["httpOnly"]=True
        if "secure" in parameters:
            cookie["secure"]=True
        result.append(cookie)
    return result

def format_request_data(request):
    assert(request)
    assert(request.content)
    urlencoded_parameters = request.get_form_urlencoded()
    if urlencoded_parameters:
        return {
            "mimeType":format_content_type(request.get_content_type()),
            "params":format_urlencoded_parameters(urlencoded_parameters),
            "text":"",
        }
    elif request.content:
        return {
            "mimeType":format_content_type(request.headers.get_first( "content-type", "unknown content type")),
            "params":[],
            "text":request.content
        }

def format_content_type(content_type):
    return content_type or ""

def format_urlencoded_parameters(urlencoded_parameters):
    if not urlencoded_parameters:
        return []
    return [{"name":key, "value":value} for key,value in urlencoded_parameters.items()]

def format_response_data(response):
    content_type = format_content_type(response.headers.get_first( "content-type", "unknown content type"))
    if response.content:
        # we always use base64, avoiding the need to check that the content is in utf8.
        # we use strip to remove the newline the base64 encoding adds
        data = binascii.b2a_base64(response.get_decoded_content()).strip()
        return {
            "size":len(data),
            "mimeType":content_type,
            "text":data,
            "encoding":"base64",
        }
    else:
        return {
            "mimeType":content_type,
            "size":0
        }

def format_redirect_url(response):
    return response.headers.get_first("location", "")

if __name__ == '__main__':
    if len(sys.argv)<3:
        print "usage: %s input_dump_file output_har_file"%sys.argv[0]
        sys.exit(0)
    input_file = open(sys.argv[1])
    flows = []
    f = flow.FlowReader(input_file).stream()

    request = None
    response = None
    client_conn = None
    server_conn = None

    for i in f:
        request =  i.request
        response = i.response
        client_conn = i.client_conn
        server_conn = i.server_conn

    if response:
        fl = Flow(request, response, client_conn, Rserver_conn)
        har = create_har(fl)
        json.dump(har, open(sys.argv[2],'w'))
    else:
        print "[!] No response, cant create HAR file without a response presently"

