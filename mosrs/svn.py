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

import ConfigParser
from ConfigParser import SafeConfigParser
from hashlib import md5
import os
from subprocess import Popen, PIPE

from mosrs.exception import AuthError, GPGError
from mosrs.message import debug, info, warning
from . import gpg

SVN_SERVERS = os.path.join(os.environ['HOME'], '.subversion', 'servers')

def get_svn_username():
    """
    Get the MOSRS username from Subversion servers file
    """
    try:
        config = SafeConfigParser()
        config.read(SVN_SERVERS)
        return config.get('metofficesharedrepos', 'username')
    except ConfigParser.Error:
        debug('Unable to retrieve MOSRS username from Subversion servers file.')
        return None

def save_svn_username(username):
    """
    Add the Rose username & server settings to Subversion servers file
    """
    # Run 'svn help' to create the config files if they don't exist
    process = Popen(
        ['svn', 'help'],
        stdout=PIPE)
    process.communicate()

    config = SafeConfigParser()
    config.read(SVN_SERVERS)

    if not config.has_section('groups'):
        config.add_section('groups')
    config.set('groups', 'metofficesharedrepos', 'code*.metoffice.gov.uk')

    if not config.has_section('metofficesharedrepos'):
        config.add_section('metofficesharedrepos')
    config.set('metofficesharedrepos', 'username', username)
    config.set('metofficesharedrepos', 'store-plaintext-passwords', 'no')

    with open(SVN_SERVERS, 'w') as config_file:
        config.write(config_file)

SVN_AUTH_DIR = os.path.join(os.environ['HOME'], '.subversion/auth/svn.simple')
SVN_PREKEY = '<https://code.metoffice.gov.uk:443> Met Office Code'
SVN_URL = 'https://code.metoffice.gov.uk/svn/test'

def get_svn_key():
    """
    Use the hexdigest of the md5 hash of
    the Subversion URL as the svn key
    """
    return md5(SVN_PREKEY).hexdigest()

def svn_username_is_saved_in_auth(username):
    """
    Check that the Subversion key and username are already stored
    """
    debug(
        'Checking that MOSRS username "{}" is stored in the Subversion auth dir.'.format(username))
    svn_key = get_svn_key()
    svn_auth_path = os.path.join(SVN_AUTH_DIR, svn_key)
    grep_prekey = Popen(
        ['grep', SVN_PREKEY, svn_auth_path],
        stdout=PIPE,
        stderr=PIPE)
    _stdout, stderr = grep_prekey.communicate()
    if grep_prekey.returncode != 0:
        debug('grep "{}" failed with:'.format(SVN_PREKEY))
        debug(stderr)
        return False
    grep_username = Popen(
        ['grep', username, svn_auth_path],
        stdout=PIPE,
        stderr=PIPE)
    _stdout, stderr = grep_username.communicate()
    if grep_username.returncode != 0:
        debug('grep "{}" failed with:'.format(username))
        debug(stderr)
        return False
    return True

def save_svn_username_in_auth(username, url=SVN_URL):
    """
    Try svn info interactively with username and url.
    This will store the Subversion key and username.
    """
    info('You need to enter your MOSRS credentials here so that Subversion can save your username.')
    process = Popen(
        ['svn', 'info', '--force-interactive', '--username', username, url],
        stdout=PIPE,
        stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    unable_message = (
        'Unable to access {} via Subversion interactively with your credentials:'.format(url))
    if process.returncode != 0:
        raise AuthError(unable_message, stderr)
    if 'Path:' in stdout:
        debug('Successfully accessed Subversion interactively with your credentials.')
    else:
        raise AuthError(unable_message, stdout)

def check_svn_username_saved_in_auth(username):
    """
    Check the realmstring and username saved by Subversion.
    Save the username if it is not already saved.
    """
    if not svn_username_is_saved_in_auth(username):
        save_svn_username_in_auth(username)
        # Check again to ensure that username is consistent
        if not svn_username_is_saved_in_auth(username):
            warning(
                'The username "{}" does not match your saved MOSRS credentials.'.format(username))
            return False
    return True

def save_svn_password(passwd):
    """
    Store the Subversion password in GPG agent
    """
    key = get_svn_key()
    gpg.preset_passphrase(key, passwd)

def get_svn_password():
    """
    Ask GPG agent for the Subversion password
    """
    key = get_svn_key()
    return gpg.get_passphrase(key)

def svn_password_is_cached():
    """
    Check if the Subversion password is cached
    """
    try:
        get_svn_password()
    except GPGError:
        # Password not in GPG
        debug('Subversion password is not cached.')
        return False
    return True

def check_svn_credentials(url=SVN_URL):
    """
    Try subversion info with url to make sure that the cached password is working
    """
    info('Checking your credentials using Subversion. Please wait.')
    process = Popen(
        ['svn', 'info', '--non-interactive', url],
        stdout=PIPE,
        stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    unable_message = 'Unable to access {} via Subversion with your credentials:'.format(url)
    if process.returncode != 0:
        raise AuthError(unable_message, stderr)
    if 'Path:' in stdout:
        info('Successfully accessed Subversion with your credentials.')
    else:
        raise AuthError(unable_message, stdout)
