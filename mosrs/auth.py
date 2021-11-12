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
from subprocess import Popen, PIPE

import requests

from . import gpg

svn_servers = os.path.join(os.environ['HOME'],'.subversion/servers')

def get_rose_username():
    """
    Get the Rose username from Subversion's config file
    """
    try:
        config = SafeConfigParser()
        config.read(svn_servers)
        return config.get('metofficesharedrepos','username')
    except Exception:
        return None

def save_rose_username(username):
    """
    Add the Rose username & server settings to Subversion's config file
    """
    # Run 'svn help' to create the config files if they don't exist
    svn = Popen(['svn','help'],stdout=PIPE)
    svn.communicate()

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

rosie_key = 'rosie:https:code.metoffice.gov.uk'
rosie_url = 'https://code.metoffice.gov.uk/rosie'

def get_rose_password():
    """
    Ask GPG agent for the Rose password
    """
    return gpg.get_passphrase(rosie_key)

def save_rose_password(passwd):
    """
    Store the Rose password in GPG agent
    """
    gpg.preset_passphrase(rosie_key,passwd)

svn_prekey = '<https://code.metoffice.gov.uk:443> Met Office Code'
svn_url = 'https://code.metoffice.gov.uk/svn/test'

def get_svn_key():
    """
    Use the hexdigest of the md5 hash of
    the Subversion URL as the svn key
    """
    return md5(svn_prekey).hexdigest()

def save_svn_password(passwd):
    """
    Store the Subversion password in GPG agent
    """
    key = get_svn_key()
    gpg.preset_passphrase(key,passwd)

def get_svn_password():
    """
    Ask GPG agent for the Subversion password
    """
    key = get_svn_key()
    return gpg.get_passphrase(key)

def request_credentials(user=None):
    """
    Request credentials from the user. If user=None then ask for the username
    as well as the password.
    """
    if user is None:
        user = raw_input('Please enter your MOSRS username: ')
    passwd = getpass('Please enter the MOSRS password for %s: '%user)
    return user, passwd

def check_credentials(url, user, passwd):
    """
    Try connecting to the Rose server with the provided credentials, raises an
    exception if this fails
    """
    r = requests.get(url, auth=(user, passwd))
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        print("\nERROR: Unable to connect to MOSRS with your credentials")
        raise
    print("\nSuccessfully authenticated with MOSRS as %s"%user)

def update(user=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """

    # Ask for credentials
    user, passwd = request_credentials(user)
    try:
        check_credentials(svn_url, user, passwd)
    except requests.exceptions.HTTPError:
        # Clear the user and try one more time
        user = None
        user, passwd = request_credentials(user)
        check_credentials(svn_url, user, passwd)

    save_rose_username(user)
    save_rose_password(passwd)
    save_svn_password(passwd)

def check_or_update():
    user = get_rose_username()
    try:
        passwd = get_rose_password()
        check_credentials(rosie_url, user, passwd)
        svn_passwd = get_svn_password()
        check_credentials(svn_url, user, svn_passwd)
    except gpg.GPGError:
        # Password not in GPG
        update(user)
    except requests.exceptions.HTTPError:
        # Testing authentication failed
        update(user)

def main():
    parser = argparse.ArgumentParser(description="Cache password to MOSRS for Rose and Subversion")
    parser.add_argument('--force',dest='force',action='store_true',help='force cache refresh of both username and password')
    args = parser.parse_args()

    try:
        if args.force:
            update(user=None)
        else:
            check_or_update()

    except requests.exceptions.HTTPError:
        print("\nERROR: Please check your credentials, if you have recently reset your password it may take a bit of time for the server to recognise the new password")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
