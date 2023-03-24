#!/usr/bin/env python3
"""
Copyright 2016 ARC Centre of Excellence for Climate Systems Science

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
from textwrap import dedent

from mosrs.exception import AuthError, GPGError, SetupError
from mosrs.host import on_accessdev
from mosrs.message import debug, info, warning, todo
from . import auth, gpg, message, network, rose, version

def prompt_or_default(prompt, default):
    """
    Ask a question with a default answer

    Returns: answer or default
    """
    response = input(f'{prompt} [{default}]: ').strip()
    if response == '':
        response = default
    return response

def check_rose():
    """
    Check the rose command
    """
    try:
        rose.check_rose()
    except AuthError as exc:
        raise SetupError(*(exc.args)) from exc

def setup_mosrs_account():
    """
    Setup MOSRS
    """
    try:
        gpg.start_gpg_agent()
    except GPGError as exc:
        warning('GPGError in setup_mosrs_account:')
        for arg in exc.args:
            info(arg)
        raise GPGError from exc

    # Save account details and cache credentials
    mosrs_request = None
    while mosrs_request not in ['yes', 'no', 'y', 'n']:
        mosrs_request = prompt_or_default('Do you have a MOSRS account', 'yes')
        mosrs_request = mosrs_request.lower()
    if mosrs_request.startswith('y'):
        try:
            auth.check_or_update()
        except AuthError as exc:
            warning('Authentication check and update failed.')
            todo(dedent(
                """
                Please check your credentials. If you have recently reset your password
                it may take a bit of time for the server to recognise the new password.
                """))
            raise SetupError from exc
    else:
        todo(dedent(
            """
            Please send a request for a MOSRS account to your MOSRS Group Sponsor,
            copying in the Lead Chief Investigator of your NCI project.
            See https://my.nci.org.au for information on your project.
            """))
        raise SetupError

def main():
    """
    The mosrs-setup console script
    """
    print()
    if on_accessdev():
        warning('This version of mosrs-setup is not intended to run on accessdev.')
        return

    program_name='mosrs-setup'
    package_version = version.version()
    program_version_message = f'{program_name} version {package_version}'
    program_description = (
        f'{program_version_message}: Set up MOSRS authentication for Rose and Subversion')
    parser = argparse.ArgumentParser(
        prog=program_name,
        description=program_description)
    parser.add_argument(
        '--debug',
        dest='debugging',
        action='store_true',
        help='enable printing of debug messages')
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

    print(
        'This script will set up your account to use Rose and the MOSRS Subversion repositories\n')

    # Check connectivity
    if not network.is_connected():
        warning('Unable to access MOSRS at this time.')
        return

    try:
        check_rose()
        try:
            setup_mosrs_account()
        except GPGError:
            return
    except SetupError:
        todo('Once this has been done please run this setup script again.')
    else:
        # Account successfully created
        info(dedent(
            """
            You are now able to use Rose and the MOSRS Subversion repositories.
            To see a list of available experiments run:

                rosie go

            Your password will be cached for a maximum of 12 hours.
            To store your password again run:

                mosrs-auth
            """))
    finally:
        info('You can ask for help with the ACCESS systems by emailing "help@nci.org.au".')

if __name__ == '__main__':
    main()
