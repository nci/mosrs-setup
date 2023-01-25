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
import io
from os import environ, mkdir, path
from subprocess import Popen, PIPE

from mosrs.backup import backup
from mosrs.exception import AuthError, GPGError
from mosrs.message import debug, info, warning, todo
from . import gpg

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

METOMI_DIR = path.join(environ['HOME'], '.metomi')
METOMI_ROSE_CONF = path.join(METOMI_DIR, 'rose.conf')

def save_rose_username(username):
    """
    Add the Rose username for prefix u to the Rose configuration file
    """
    debug('Saving MOSRS username "{}" to Rose config.'.format(username))
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
    if not path.exists(METOMI_DIR):
        mkdir(METOMI_DIR, 0o755)
    # Backup the ~/.metomi directory
    backup('.metomi')
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
    except GPGError:
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
    unable_message = 'Unable to access rosie prefix {} with your credentials:'.format(prefix)
    if process.returncode != 0:
        raise AuthError(unable_message, stderr)
    stdout = '' if stdout is None else stdout
    if 'Hello ' + username in stdout:
        info('Successfully accessed rosie with your credentials.')
    else:
        raise AuthError(unable_message, stdout)

def todo_check_rose_username():
    """
    Print a todo message
    """
    todo('Check {} in {}.'.format(PREFIX_USERNAME_KEY, METOMI_ROSE_CONF))
