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
import os
import argparse
from getpass import getpass
import ConfigParser
from ConfigParser import SafeConfigParser
from hashlib import md5
from subprocess import Popen, PIPE
from textwrap import dedent
import io

from mosrs.host import on_accessdev
from mosrs.message import debug, info, warning, todo
from . import gpg, message

class AuthError(Exception):
    """
    Indicates an anticipated error
    """
    pass

ROSE_UNABLE_MESSAGE = 'Unable to find Rose.'

def rose_is_found():
    """
    Test if which can find the rose command
    """
    debug('Checking the rose command.')
    try:
        command = Popen(
            ['which', 'rose'],
            stdout=PIPE,
            stderr=PIPE)
        stdout, stderr = command.communicate()
    except OSError as exc:
        raise AuthError(*(exc.args))
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    if command.returncode != 0:
        debug('{} {}'.format(ROSE_UNABLE_MESSAGE, stderr))
    return command.returncode == 0

def check_rose():
    """
    Check the rose command
    """
    try:
        if not rose_is_found():
            raise AuthError
    except AuthError:
        warning(ROSE_UNABLE_MESSAGE)
        todo('Please ensure that the correct modules are loaded.')
        raise

PREFIX_USERNAME_KEY = 'prefix-username.u'

def get_rose_username():
    """
    Get the MOSRS username from the Rosie configuration for prefix u
    """
    unable_message = 'Unable to retrieve MOSRS username from Rose config.'
    try:
        rose_config = Popen(
            ['rose', 'config'],
            stdout=PIPE,
            stderr=PIPE)
        grep_prefix = Popen(
            ['grep', '^ *{} *='.format(PREFIX_USERNAME_KEY)],
            stdin=rose_config.stdout,
            stdout=PIPE,
            stderr=PIPE)
        rose_config.stdout.close()
        stdout, stderr = grep_prefix.communicate()
    except OSError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    if not (grep_prefix.returncode == 0 and PREFIX_USERNAME_KEY in stdout):
        debug(unable_message)
        return None
    rose_username_def = '[rosie-id]\n' + stdout
    config = SafeConfigParser()
    config.readfp(io.BytesIO(rose_username_def))
    try:
        return config.get('rosie-id', PREFIX_USERNAME_KEY)
    except ConfigParser.Error:
        debug(unable_message)
        return None

METOMI_DIR = os.path.join(os.environ['HOME'], '.metomi')
METOMI_ROSE_CONF = os.path.join(METOMI_DIR, 'rose.conf')

def save_rose_username(username):
    """
    Add the Rose username for prefix u to the Rose configuration file
    """
    config = SafeConfigParser()
    config.add_section('rosie-id')
    config.set('rosie-id', PREFIX_USERNAME_KEY, username)
    # Write the config to a string
    with io.BytesIO() as config_file:
        config.write(config_file)
        # Wind back the file to read it
        config_file.seek(0)
        # Remove spaces from " = " delimiter
        # Rose configuration examples do not use " = "
        config_str = config_file.read().replace(' = ', '=', 1)
    # Create ~/.metomi directory if it does not exist
    try:
        os.mkdir(METOMI_DIR, 0o755)
    except OSError:
        pass
    # Append the config string to the Rose configuration
    with open(METOMI_ROSE_CONF, 'a') as rose_conf_file:
        rose_conf_file.write(config_str)

ROSE_KEY = 'rosie:https:code.metoffice.gov.uk'

def save_rose_password(passwd):
    """
    Store the Rose password in GPG agent
    """
    gpg.preset_passphrase(ROSE_KEY, passwd)

def get_rose_password():
    """
    Ask GPG agent for the Rose password
    """
    return gpg.get_passphrase(ROSE_KEY)

def rose_password_is_cached():
    """
    Check if the Rose password is cached
    """
    try:
        get_rose_password()
    except gpg.GPGError:
        # Password not in GPG
        debug('Rose password is not cached.')
        return False
    return True

def check_rose_credentials(username, prefix='u'):
    """
    Try rosie hello with prefix to make sure that the cached password is working
    """
    info('Checking your credentials using rosie. Please wait.')
    process = Popen(
        ['rosie', 'hello', '--prefix={}'.format(prefix)],
        stdout=PIPE,
        stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    unable_message = 'Unable to access rosie prefix {} with your credentials:'.format(prefix)
    if process.returncode != 0:
        raise AuthError(unable_message, stderr)
    if 'Hello ' + username in stdout:
        info('Successfully accessed rosie with your credentials.')
    else:
        raise AuthError(unable_message, stdout)

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
    debug('Checking that username "{}" is stored in the Subversion auth dir.'.format(username))
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

def save_svn_username_in_auth(username, url):
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
        save_svn_username_in_auth(username, SVN_URL)
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
    except gpg.GPGError:
        # Password not in GPG
        debug('Subversion password is not cached.')
        return False
    return True

def check_svn_credentials(url):
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

def request_credentials(username=None):
    """
    Request credentials from the user. If username=None then ask for the username
    as well as the password.
    """
    info('You need to enter your MOSRS credentials here so that GPG can cache your password.')
    if username is None:
        username = raw_input('Please enter your MOSRS username: ')
    passwd = getpass('Please enter the MOSRS password for {}: '.format(username))
    return username, passwd

def request_and_save_credentials(rose_username=None, svn_username=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """
    if svn_username is None:
        svn_username = rose_username
    # Ask for credentials
    username, passwd = request_credentials(svn_username)
    # Check against the realmstring and username stored by Subversion.
    # Save the realmstring and username if not already saved.
    if not check_svn_username_saved_in_auth(username):
        raise AuthError
    # Check consistency of saved MOSRS usernames
    if (rose_username is not None and username != rose_username):
        warning('Your saved MOSRS username is inconsistent.')
        todo('Check {} in {}.'.format(PREFIX_USERNAME_KEY, METOMI_ROSE_CONF))
        raise AuthError
    # Save credentials
    if rose_username is None:
        save_rose_username(username)
    save_svn_username(username)
    try:
        save_rose_password(passwd)
        save_svn_password(passwd)
    except gpg.GPGError as exc:
        warning('Saving credentials failed.')
        for arg in exc.args:
            debug(arg)
        raise AuthError
    return username

def update(rose_username, svn_username=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """
    debug('MOSRS Rose username passed to update is {}.'.format(rose_username))
    debug('MOSRS Subversion username passed to update is {}.'.format(svn_username))
    try:
        # Ask for credentials from the user and save in the GPG agent
        username = request_and_save_credentials(rose_username, svn_username)
        # Check Subversion credentials
        check_svn_credentials(SVN_URL)
    except AuthError:
        # Clear the user and try one more time
        warning('Subversion authentication failed.')
        if rose_username is not None:
            todo('Check {} in {}.'.format(PREFIX_USERNAME_KEY, METOMI_ROSE_CONF))
            raise
        # Ask for credentials from the user and save in the GPG agent
        username = request_and_save_credentials()
        # Check Subversion credentials
        check_svn_credentials(SVN_URL)
    # Check Rose credentials separately, allowing failure
    try:
        check_rose_credentials(username)
    except AuthError as exc:
        warning('Rose authentication failed.')
        for arg in exc.args:
            info(arg)

def check_or_update():
    """
    Check that credentials are cached and work,
    otherwise call update to obtain new credentials
    """
    rose_username = get_rose_username()
    if rose_username is not None:
        debug('MOSRS username stored in Rose config is {}.'.format(rose_username))
    svn_username = get_svn_username()
    if svn_username is not None:
        debug('MOSRS username stored in Subversion servers file is {}.'.format(svn_username))

    if svn_username is None:
        update(rose_username)
        return
    # Check the realmstring and svn_username stored by Subversion
    if not check_svn_username_saved_in_auth(svn_username):
        info('Try again.')
        update(rose_username)
        return
    # Check Subversion password cache
    if not svn_password_is_cached():
        update(rose_username, svn_username)
        return
    # Check consistency of saved MOSRS usernames
    if (rose_username is not None and svn_username != rose_username):
        warning('Your saved MOSRS username is inconsistent.')
        todo('Check {} in {}.'.format(PREFIX_USERNAME_KEY, METOMI_ROSE_CONF))
        raise AuthError
    # Check Subversion credentials
    try:
        check_svn_credentials(SVN_URL)
    except AuthError as exc:
        warning('Subversion authentication with cached credentials failed.')
        for arg in exc.args:
            info(arg)
        update(rose_username, svn_username)
        return
    # Check Rose password cache
    if not rose_password_is_cached():
        update(rose_username, svn_username)
        return
    # Check Rose credentials, allowing failure
    try:
        check_rose_credentials(svn_username)
    except AuthError as exc:
        info('Rose authentication with cached credentials failed.')
        for arg in exc.args:
            info(arg)

def start_gpg_agent():
    """
    Start the GPG agent if it has not already started
    """
    try:
        gpg.start_gpg_agent()
    except gpg.GPGError as exc:
        warning('GPGError in start_gpg_agent:')
        for arg in exc.args:
            info(arg)
        raise AuthError

def main():
    """
    The mosrs-auth console script
    """
    if on_accessdev():
        warning('This version of mosrs-auth is not intended to run on accessdev.')
        return

    parser = argparse.ArgumentParser(description='Cache password to MOSRS for Rose and Subversion')
    parser.add_argument(
        '--debug',
        dest='debugging',
        action='store_true',
        help='enable printing of debug messages')
    parser.add_argument(
        '--force',
        dest='force',
        action='store_true',
        help='force cache refresh of both username and password')
    args = parser.parse_args()

    if args.debugging:
        message.debugging = True

    contact_helpdesk = 'Please contact the helpdesk.'

    # Check the rose command
    try:
        check_rose()
    except AuthError:
        todo(contact_helpdesk)
        return

    # Start the GPG agent if it has not already started
    try:
        start_gpg_agent()
    except AuthError:
        todo(contact_helpdesk)
        return

    # Check or update the user's credentials
    try:
        if args.force:
            update(get_rose_username())
        else:
            check_or_update()
    except AuthError:
        todo(dedent(
            """
            Please check your credentials. If you have recently reset your password
            it may take a bit of time for the server to recognise the new password.
            """))

if __name__ == '__main__':
    main()
