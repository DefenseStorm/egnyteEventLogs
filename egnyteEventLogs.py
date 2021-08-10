#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
from datetime import datetime
from datetime import timedelta
import base64

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    audit_JSON_field_mappings = {
        'occurred' : 'timestamp'
    }

    access_JSON_field_mappings = {
        'occurred' : 'timestamp'
    }

    def egnyte_basicAuth(self):
        url = self.api_url + '/puboauth/token'
        self.ds.log('INFO', "Attempting basic auth to  url: " + url)
        params = {
                'Content-Type': 'application/x-www-form-urlencoded',
                }
        data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'Egnyte.filesystem',
                }
        try:
            response = requests.post(url, headers = params, data = data)
        except Exception as e:
            self.ds.log('ERROR', "Exception in egnyte_request: {0}".format(str(e)))
            traceback.print_exc()
            return None
        if not response or response.status_code != 200:
            self.ds.log('ERROR', "Received unexpected " + '[' + str(response.status_code) + ']:' + response.text + " response from Egnyte Server {0}.".format(url))
            self.ds.log('ERROR', "Exiting due to unexpected response.")
            sys.exit(0)
        if response == None and response.headers == None:
            return None
        r_json = response.json()
        access_token = r_json['access_token']
        return access_token

    def egnyte_cursor(self):
        response = self.egnyte_request('/pubapi/v2/events/cursor')
        r_json = response.json()
        self.ds.log('INFO', "Oldest Event cursor %s" %(r_json['oldest_event_id']))
        return r_json['oldest_event_id']


    def egnyte_getEvents(self):
        self.ds.log('INFO', "Getting events from cursor: %d" %self.cursor)
        total_events = []

        while True:

            response = self.egnyte_request('/pubapi/v2/events?count=100&id=' + str(self.cursor))
            if response.status_code == 204:
                break
            r_json = response.json()
            print(r_json)
            self.cursor = r_json['latest_id']
            total_events += r_json['events']
            time.sleep(1)
        if len(total_events) == 0:
            self.ds.log('INFO', "No events to retreive.")
            return
        return total_events


    def egnyte_request(self, path, params = None, data = None, verify=False, proxies=None):
        url = self.api_url + path
        headers = {
                'Authorization': 'Bearer ' + self.token
            }
        self.ds.log('INFO', "Attempting to connect to url: " + url + "with headers: " + json.dumps(headers) + ", with params: " + json.dumps(params) + " ,data: " + json.dumps(data))
        try:
            response = requests.get(url, headers=headers, params = params, data = data, timeout=15,
                                    verify=verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception in egnyte_request: {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            if response.status_code == 401:
                self.ds.log('WARNING', "Failed.  Retrying Basic Auth: "+ str(response.text) + " response from Egnyte Server {0}.".format(url))
                try:
                    self.token = self.egnyte_basicAuth()
                except Exception as e:
                    self.ds.log('ERROR', "Exception in egnyte_request: {0}".format(str(e)))
                    return None
                try:
                    response = requests.get(url, headers=headers, params = params, data = data, timeout=15,
                                        verify=verify, proxies=proxies)
                except Exception as e:
                    self.ds.log('ERROR', "Exception in egnyte_request after re-auth: {0}".format(str(e)))
                    return None
            elif response.status_code == 204:
                self.ds.log('INFO', "Response code (204).  Nothing to do.")
                return response
            else:
                self.ds.log('ERROR', "Received unexpected " + str(response.text) + " response from Egnyte Server {0}.".format(url))
                self.ds.log('ERROR', "Exiting due to unexpected response.")
                sys.exit(0)
        return response



    def egnyte_main(self): 

        self.api_url = self.ds.config_get('egnyte', 'api_url')
        self.state_dir = self.ds.config_get('egnyte', 'state_dir')
        self.username = self.ds.config_get('egnyte', 'username')
        self.password = self.ds.config_get('egnyte', 'password')
        self.client_id = self.ds.config_get('egnyte', 'client_id')
        self.client_secret = self.ds.config_get('egnyte', 'client_secret')
        state_info = self.ds.get_state(self.state_dir)
        if state_info != None:
            self.cursor = state_info['cursor']
            self.token = state_info['token']
        else:
            self.token = self.egnyte_basicAuth()
            self.cursor = self.egnyte_cursor()

        if self.token == None or self.token == '':
            self.ds.log('ERROR', "Invalid Configuration or auth failed.  No token available")
            return None

        events = self.egnyte_getEvents()

        if events == None:
            self.ds.log('INFO', "There are no event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} event logs".format(len(events)))
            for log in events:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.audit_JSON_field_mappings, flatten = False)

        state_info = {'cursor':self.cursor, 'token':self.token}
        self.ds.set_state(self.state_dir, state_info)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('egnyte', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.egnyte_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
        print('  -g    Authenticate to Get Token then exit')
        print
    
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htlg")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('egnyteEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
