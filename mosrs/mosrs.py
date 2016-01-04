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
import os
import argparse
from getpass import getpass
from ConfigParser import SafeConfigParser
from hashlib import md5

import requests

from . import gpg

svn_servers = os.path.join(os.environ['HOME'],'.subversion/servers')

def get_rose_username():
    try:
        config = SafeConfigParser()
        config.read(svn_servers)
        return config.get('metofficesharedrepos','username')
    except Exception:
        return None

def save_rose_username(username):
    config = SafeConfigParser()
    config.read(svn_servers)

    if not config.has_section('groups'):
        config.add_section('groups')
    config.set('groups','metofficesharedrepos','code*.metoffice.gov.uk')

    if not config.has_section('metofficesharedrepos'):
        config.add_section('metofficesharedrepos')
    config.set('metofficesharedrepos','username',username)
    config.set('metofficesharedrepos','store-plaintext-passwords','no')

    with open(svn_servers, 'w') as f:
        config.write(f)

def get_rose_password():
    return gpg.get_passphrase('rosie:https:code.metoffice.gov.uk')

def save_rose_password(passwd):
    gpg.preset_passphrase('rosie:https:code.metoffice.gov.uk',passwd)

def save_svn_password(passwd):
    key = md5('<https://code.metoffice.gov.uk:443> Met Office Code').hexdigest()
    gpg.preset_passphrase(key,passwd)

def request_credentials(user=None):
    if user is None:
        user = raw_input('Please enter your MOSRS username: ')
    passwd = getpass('Please enter your MOSRS password: ')
    return user, passwd

def check_credentials(user, passwd):
    r = requests.get('https://code.metoffice.gov.uk/rosie', auth=(user, passwd))
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        print("\nERROR: Unable to connect to MOSRS with your credentials")
        raise
    print("\nSuccessfully authenticated with MOSRS")

def update(force=False):
    if force:
        user = None
    else:
        user = get_rose_username()

    # Ask for credentials
    user, passwd = request_credentials(user)
    try:
        check_credentials(user, passwd)
    except requests.exceptions.HTTPError:
        # Clear the user and try one more time
        user = None
        user, passwd = request_credentials(user)
        check_credentials(user, passwd)

    save_rose_username(user)
    save_rose_password(passwd)
    save_svn_password(passwd)

def check_cache():
    user   = get_rose_username()
    passwd = get_rose_password()
    check_credentials(user, passwd)

def main():
    parser = argparse.ArgumentParser(description="Cache password to MOSRS for Rose and Subversion")
    parser.add_argument('--force',dest='force',action='store_true',help='force cache refresh of both username and password')
    args = parser.parse_args()

    try:
        if args.force:
            update(force=True)
        else:
            try:
                check_cache()
            except Exception:
                update()
    except requests.exceptions.HTTPError:
        print("\nERROR: Please check your credentials, if you have recently reset your password it may take a bit of time for the server to recognise the new password")

if __name__ == '__main__':
    main()
