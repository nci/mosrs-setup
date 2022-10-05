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

from . import gpg, host
from host import get_host, on_accessdev
from message import info, warning, todo

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
    process = Popen(['svn','help'],stdout=PIPE)
    process.communicate()

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

rose_key = 'rosie:https:code.metoffice.gov.uk'

def get_rose_password():
    """
    Ask GPG agent for the Rose password
    """
    return gpg.get_passphrase(rose_key)

def save_rose_password(passwd):
    """
    Store the Rose password in GPG agent
    """
    gpg.preset_passphrase(rose_key,passwd)

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

def check_rose_credentials(user, prefix='u'):
    """
    Try rosie hello with prefix to make sure that the cached password is working
    """
    command = ['rosie', 'hello', '--prefix=' + prefix]
    process = Popen(
            command, 
            stdout=PIPE, 
            stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    unable_message = '\nWARNING: Unable to access rosie prefix %s with your credentials.\n'%prefix
    if process.returncode != 0:
        raise Exception(unable_message + stderr)
    if 'Hello ' + user in stdout:
        info('Successfully accessed rosie with your credentials.')
    else:
        raise Exception(unable_message + stdout)

def check_svn_credentials(url):
    """
    Try subversion info with url to make sure that the cached password is working
    """
    command = ['svn', 'info', '--non-interactive', svn_url]
    process = Popen(
            command, 
            stdout=PIPE, 
            stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    unable_message = 'Unable to access {} via Subversion with your credentials.\n'.format(svn_url)
    if process.returncode != 0:
        raise Exception(unable_message + stderr)
    if 'Path:' in stdout:
        info('Successfully accessed Subversion with your credentials.')
    else:
        raise Exception(unable_message + stdout)

def update(user=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """

    # Ask for credentials
    user, passwd = request_credentials(user)
    try:
        save_rose_username(user)
        save_rose_password(passwd)
        save_svn_password(passwd)
    except Exception as e:
        warning('Saving credentials failed in update.')
        print(type(e))
        for arg in e.args:
            info(arg)
        raise
    try:
        check_svn_credentials(svn_url)
    except:
        # Clear the user and try one more time
        warning('Subversion authentication failed in update.')
        user = None
        user, passwd = request_credentials(user)
        save_rose_username(user)
        save_rose_password(passwd)
        save_svn_password(passwd)
        check_svn_credentials(svn_url)
    # Check Rose credentials separately, allowing failure
    try:
        check_rose_credentials(user)
    except Exception as e:
        warning('Rose authentication failed in update.')
        print(type(e))
        for arg in e.args:
            info(arg)

def check_or_update():
    user = get_rose_username()
    if user is None:
        update()
        return
    # Check Subversion password cache
    try:
        get_svn_password()
    except gpg.GPGError as e:
        # Password not in GPG
        warning('Subversion password is not in GPG.')
        update(user)
        return
    except Exception as e:
        warning('Subversion password retrieval failed.')
        for arg in e.args:
            info(arg)
        update(user)
        return
    # Check Subversion credentials
    try:
        check_svn_credentials(svn_url)
    except Exception as e:
        # Authentication failed
        warning('Subversion authentication failed.')
        for arg in e.args:
            info(arg)
        update(user)
        return
    # Check Rose password cache
    try:
        get_rose_password()
    except gpg.GPGError as e:
        # Password not in GPG
        warning('Rose password is not in GPG.')
        update(user)
        return
    except Exception as e:
        warning('Rose password retrieval failed.')
        for arg in e.args:
            info(arg)
        update(user)
        return
    # Check Rose credentials, allowing failure
    try:
        check_rose_credentials(user)
    except Exception as e:
        warning('Rose authentication failed.')
        for arg in e.args:
            info(arg)

def main():
    if on_accessdev():
        warning('This version of mosrs-auth is not intended to run on accessdev.')
        return

    parser = argparse.ArgumentParser(description="Cache password to MOSRS for Rose and Subversion")
    parser.add_argument('--force',dest='force',action='store_true',help='force cache refresh of both username and password')
    args = parser.parse_args()

    try:
        gpg.send('GETINFO version')
        gpg.set_environ()
        if args.force:
            update(user=None)
        else:
            check_or_update()
    except Exception as e:
        for arg in e.args:
            info(arg)
        todo('Please check your credentials.'
           + 'If you have recently reset your password it may take a bit of time for the server to recognise the new password.')

if __name__ == '__main__':
    main()
