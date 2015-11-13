#!/usr/bin/env python
"""
Copyright 2015 ARC Centre of Excellence for Climate Systems Science

author: Scott Wales <scott.wales@unimelb.edu.au>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import print_function
import sys
from getpass import getpass
import requests
from ConfigParser import SafeConfigParser

def setup():
    helptext = """
    Welcome to the Accessdev initial setup
    --------------------------------------

    This process will set up your account on Accessdev to use the Met Office
    Shared Repository System (mosrs) and Rose/Cylc
    """
    print(helptext)

    user, passwd = request_creds()
    check_creds(user, passwd)
    setup_subversion_servers(user)

def request_creds(user=None):
    if user is None:
        user = raw_input('Please enter your MOSRS username: ')
    passwd = getpass('Please enter your MOSRS password: ')
    return user, passwd

def check_creds(user, passwd):
    r = requests.get('https://code.metoffice.gov.uk/rosie', auth=(user, passwd))
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        print("\nERROR: Unable to connect to MOSRS with your credentials")
        raise
    print("\nSuccessfully authenticated with MOSRS")

def setup_subversion_servers(user):
    config = SafeConfigParser()
    filename = '~/.subversion/servers'
    config.read(filename)

    if not config.has_section('groups'):
        config.add_section('groups')
    config.set('groups','metofficesharedrepos','code*.metoffice.gov.uk')

    if not config.has_section('metofficesharedrepos'):
        config.add_section('metofficesharedrepos')
    config.set('metofficesharedrepos','username',user)
    config.set('metofficesharedrepos','store-plaintext-passwords','no')

    with open(filename, 'w') as f:
        config.write(f)

def get_username():
    config = SafeConfigParser()
    filename = '~/.subversion/servers'
    config.read(filename)
    return config.get('metofficesharedrepos','username')

if __name__ == '__main__':
    setup()
