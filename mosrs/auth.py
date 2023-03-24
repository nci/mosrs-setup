#!/usr/bin/env python3
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

import argparse
from getpass import getpass
from textwrap import dedent

from mosrs.exception import AuthError, GPGError
from mosrs.host import on_accessdev
from mosrs.message import debug, info, warning, todo
from . import gpg, message, network, rose, svn, version

def request_credentials(username=None):
    """
    Request credentials from the user. If username=None then ask for the username
    as well as the password.
    """
    info('You need to enter your MOSRS credentials here so that GPG can cache your password.')
    if username is None:
        username = input('Please enter your MOSRS username: ')
    passwd = getpass(f'Please enter the MOSRS password for {username}: ')
    return username, passwd

PLAINTEXT_PASSWORD_MESSAGE = (
    "Your current Subversion configuration for MOSRS permits plaintext passwords. "
    "It will be changed so that only encrypted passwords are stored.")

def request_and_save_credentials(rose_username=None, svn_username=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """
    # Ask for credentials
    username, passwd = request_credentials(svn_username)
    # Check if the Subversion servers file allows plaintext passwords to be stored
    plaintext = svn.svn_servers_stores_plaintext_passwords()
    if plaintext:
        warning(PLAINTEXT_PASSWORD_MESSAGE)
    # Check against the realmstring and username stored by Subversion.
    # Save the realmstring and username if not already saved.
    if not svn.check_svn_username_saved_in_auth(username, plaintext):
        raise AuthError
    # Check consistency of saved MOSRS usernames
    if (rose_username is not None and username != rose_username):
        warning('Your saved MOSRS username is inconsistent.')
        rose.todo_check_rose_username()
        raise AuthError
    # Save credentials
    svn.save_svn_username(username, plaintext)
    if rose_username is None:
        rose.save_rose_username(username)
    try:
        rose.save_rose_password(passwd)
        svn.save_svn_password(passwd)
    except GPGError as exc:
        warning('Saving credentials failed.')
        for arg in exc.args:
            debug(arg)
        raise AuthError from exc
    return username

def update(rose_username=None, svn_username=None):
    """
    Ask for credentials from the user & save in the GPG agent
    """
    debug(f'MOSRS Rose username passed to update is "{rose_username}".')
    debug(f'MOSRS Subversion username passed to update is "{svn_username}".')
    if svn_username is None:
        svn_username = rose_username
    try:
        # Ask for credentials from the user and save in the GPG agent
        username = request_and_save_credentials(rose_username, svn_username)
        # Check Subversion credentials
        svn.check_svn_credentials()
    except AuthError:
        # Clear the user and try one more time
        warning('Subversion authentication failed.')
        if rose_username is not None:
            rose.todo_check_rose_username()
            raise
        # Ask for credentials from the user and save in the GPG agent
        username = request_and_save_credentials()
        # Check Subversion credentials
        svn.check_svn_credentials()
    # Save Rose username if necessary
    if rose_username is None:
        rose.save_rose_username(username)
    # Check Rose credentials separately, allowing failure
    try:
        rose.check_rose_credentials(username)
    except AuthError as exc:
        warning('Rose authentication failed.')
        for arg in exc.args:
            info(arg)

def check_or_update():
    """
    Check that credentials are cached and work,
    otherwise call update to obtain new credentials
    """
    rose_username = rose.get_rose_username()
    if rose_username is not None:
        debug(f'MOSRS username stored in Rose config is "{rose_username}".')
    svn_username = svn.get_svn_username()
    if svn_username is None:
        update(rose_username)
        return
    debug(f'MOSRS username stored in Subversion servers file is "{svn_username}".')

    # Check if the Subversion servers file allows plaintext passwords to be stored
    plaintext = svn.svn_servers_stores_plaintext_passwords()
    if plaintext:
        warning(PLAINTEXT_PASSWORD_MESSAGE)
    # Check the realmstring and svn_username stored by Subversion
    if not svn.check_svn_username_saved_in_auth(svn_username, plaintext):
        info('Try again.')
        update(rose_username)
        return
    # Check Subversion password cache
    if not svn.svn_password_is_cached():
        update(rose_username, svn_username)
        return
    # Check consistency of saved MOSRS usernames
    if (rose_username is not None and svn_username != rose_username):
        warning('Your saved MOSRS username is inconsistent.')
        rose.todo_check_rose_username()
        raise AuthError
    # Check Subversion credentials
    try:
        svn.check_svn_credentials()
    except AuthError as exc:
        warning('Subversion authentication with cached credentials failed.')
        for arg in exc.args:
            info(arg)
        update(rose_username, svn_username)
        return
    # Check Rose password cache
    if not rose.rose_password_is_cached():
        update(rose_username, svn_username)
        return
    # Save Rose username if necessary
    if rose_username is None:
        rose.save_rose_username(svn_username)
    # Check Rose credentials, allowing failure
    try:
        rose.check_rose_credentials(svn_username)
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
    except GPGError as exc:
        warning('GPGError in start_gpg_agent:')
        for arg in exc.args:
            info(arg)
        raise AuthError from exc

def main():
    """
    The mosrs-auth console script
    """
    if on_accessdev():
        warning('This version of mosrs-auth is not intended to run on accessdev.')
        return
    program_name = 'mosrs-auth'
    package_version = version.version()
    program_version_message = f'{program_name} version {package_version}'
    program_description = (
        f'{program_version_message}: cache password to MOSRS for Rose and Subversion')
    parser = argparse.ArgumentParser(
        prog=program_name,
        description=program_description)
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
    parser.add_argument(
        '--version',
        dest='version',
        action='store_true',
        help='print version information and exit')
    args = parser.parse_args()

    if args.debugging:
        message.debugging = True
        debug(program_version_message)
    if args.version:
        print(program_version_message)
        return

    contact_helpdesk = 'Please contact the helpdesk.'

    # Check connectivity
    if not network.is_connected():
        warning('Unable to access MOSRS at this time.')
        return

    # Check the rose command
    try:
        rose.check_rose()
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
            update()
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
