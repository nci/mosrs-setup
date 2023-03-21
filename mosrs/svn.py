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

from configparser import SafeConfigParser
from configparser import Error as ConfigParserError
from hashlib import md5
from os import environ, mkdir, path, remove
from subprocess import Popen, PIPE

from mosrs.backup import backup
from mosrs.encoding import communicate, ENCODING
from mosrs.exception import AuthError, GPGError
from mosrs.message import debug, info, warning
from . import gpg

SVN_BASENAME = '.subversion'
SVN_DIR = path.join(environ['HOME'], SVN_BASENAME)
SVN_SERVERS = path.join(SVN_DIR, 'servers')

def backup_svn():
    """
    Backup the ~/.subversion directory
    """
    if not path.exists(SVN_DIR):
        mkdir(SVN_DIR, 0o700)
    backup(SVN_BASENAME)

def svn_servers_stores_plaintext_passwords():
    """
    Check that the Subversion servers file
    allows plaintext passwords for metofficesharedrepos
    """
    debug(
        'Checking if the Subversion servers file '
        'allows plaintext passwords for "metofficesharedrepos".')
    try:
        config = SafeConfigParser()
        config.read(SVN_SERVERS)
    except ConfigParserError:
        debug('Unable to check Subversion servers file.')
        return False

    if not config.has_section('groups'):
        return False
    if not config.has_section('metofficesharedrepos'):
        return False
    plaintext = config.get('metofficesharedrepos', 'store-plaintext-passwords')
    debug('store-plaintext-passwords == "{}"'.format(plaintext))
    return plaintext != 'no'

def create_svn_config():
    """
    Run 'svn help' to create the Subversion config files if they don't exist
    """
    with Popen(
            ['svn', 'help'],
        stdout=PIPE) as process:
        communicate(process)

def get_svn_username():
    """
    Get the MOSRS username from Subversion servers file
    """
    try:
        config = SafeConfigParser()
        config.read(SVN_SERVERS)
        return config.get('metofficesharedrepos', 'username')
    except ConfigParserError:
        debug('Unable to retrieve MOSRS username from Subversion servers file.')
        return None

def save_svn_username(username, plaintext=False):
    """
    Add the Rose username & server settings to Subversion servers file
    """

    debug('Checking to see if Subversion servers file needs to be changed.')
    # Check to see if the Subversion servers file needs to be changed
    if not plaintext:
        old_username = get_svn_username()
        if old_username == username:
            debug('The Subversion servers file does not need to be changed.')
            return

    debug('Saving Subversion username "{}".'.format(username))
    # Backup the ~/.subversion directory
    backup_svn()

    # Create the config files if they don't exist
    create_svn_config()

    config = SafeConfigParser()
    config.read(SVN_SERVERS)

    if not config.has_section('groups'):
        config.add_section('groups')
    config.set('groups', 'metofficesharedrepos', 'code*.metoffice.gov.uk')

    if not config.has_section('metofficesharedrepos'):
        config.add_section('metofficesharedrepos')
    config.set('metofficesharedrepos', 'username', username)
    config.set('metofficesharedrepos', 'store-plaintext-passwords', 'no')
    # Write the config
    with open(SVN_SERVERS, 'w', encoding=ENCODING) as config_file:
        config.write(config_file)

SVN_AUTH_DIR = path.join(SVN_DIR, 'auth', 'svn.simple')
SVN_PREKEY = '<https://code.metoffice.gov.uk:443> Met Office Code'
SVN_URL = 'https://code.metoffice.gov.uk/svn/test'

def get_svn_key():
    """
    Use the hexdigest of the md5 hash of
    the Subversion URL as the svn key
    """
    return md5(SVN_PREKEY.encode()).hexdigest()

def svn_username_is_saved_in_auth(username):
    """
    Check that the Subversion key and username are already stored
    """
    debug(
        'Checking that MOSRS username "{}" is stored in the Subversion auth dir.'.format(username))
    svn_key = get_svn_key()
    svn_auth_path = path.join(SVN_AUTH_DIR, svn_key)
    with Popen(
        ['grep', SVN_PREKEY, svn_auth_path],
        stdout=PIPE,
        stderr=PIPE) as grep_prekey:
        _ignore, stderr = communicate(grep_prekey)
        if grep_prekey.returncode != 0:
            debug('grep "{}" failed with:'.format(SVN_PREKEY))
            debug(stderr)
            return False
    with Popen(
        ['grep', username, svn_auth_path],
        stdout=PIPE,
        stderr=PIPE) as grep_username:
        _ignore, stderr = communicate(grep_username)
        if grep_username.returncode != 0:
            debug('grep "{}" failed with:'.format(username))
            debug(stderr)
            return False
    return True

def remove_svn_auth():
    """
    Remove the Subversion auth file corresponding to the svn_key.
    """
    svn_key = get_svn_key()
    svn_auth_path = path.join(SVN_AUTH_DIR, svn_key)
    debug('Removing {}.'.format(svn_auth_path))
    # Backup the ~/.subversion directory
    backup_svn()
    try:
        if path.exists(svn_auth_path):
            remove(svn_auth_path)
    except OSError as exc:
        warning('Removing {} failed.'.format(svn_auth_path))
        for arg in exc.args[1:]:
            info(arg)
        raise AuthError from exc

def save_svn_username_in_auth(username):
    """
    Try svn info interactively with username and url.
    This will store the Subversion key and username.
    """
    debug('Saving Subversion username "{}" in the auth directory.'.format(username))
    # Backup the ~/.subversion directory
    backup_svn()
    # Try svn info
    info('You need to enter your MOSRS credentials here so that Subversion can save your username.')
    url = SVN_URL
    with Popen(
        ['svn', 'info', '--force-interactive', '--username', username, url],
        stdout=PIPE,
        stderr=PIPE) as process:
        stdout, stderr = communicate(process)
        unable_message = (
            'Unable to access {} via Subversion interactively with your credentials:'.format(url))
        if process.returncode != 0:
            raise AuthError(unable_message, stderr)
        if 'Path:' in stdout:
            debug('Successfully accessed Subversion interactively with your credentials.')
        else:
            raise AuthError(unable_message, stdout)

def check_svn_username_saved_in_auth(username, plaintext=False):
    """
    Check the realmstring and username saved by Subversion.
    Save the username if it is not already saved.
    """
    if plaintext:
        remove_svn_auth()
    if not svn_username_is_saved_in_auth(username):
        if plaintext:
            save_svn_username(username, plaintext)
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
    debug("Saving the Subversion password.")
    key = get_svn_key()
    gpg.preset_passphrase(key, passwd)

def get_svn_password():
    """
    Ask GPG agent for the Subversion password
    """
    debug("Getting the Subversion password.")
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
        debug('The Subversion password is not cached.')
        return False
    return True

def check_svn_credentials(url=SVN_URL):
    """
    Try subversion info with url to make sure that the cached password is working
    """
    info('Checking your credentials using Subversion. Please wait.')
    with Popen(
        ['svn', 'info', '--non-interactive', url],
        stdout=PIPE,
        stderr=PIPE) as process:
        stdout, stderr = communicate(process)
        unable_message = 'Unable to access {} via Subversion with your credentials:'.format(url)
        if process.returncode != 0:
            raise AuthError(unable_message, stderr)
        stdout = '' if stdout is None else stdout
        if 'Path:' in stdout:
            info('Successfully accessed Subversion with your credentials.')
        else:
            raise AuthError(unable_message, stdout)
