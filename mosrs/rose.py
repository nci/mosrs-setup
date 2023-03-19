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

METOMI_BASENAME = '.metomi'
METOMI_DIR = path.join(environ['HOME'], METOMI_BASENAME)
METOMI_ROSE_CONF = path.join(METOMI_DIR, 'rose.conf')

def backup_metomi():
    """
    Backup the ~/.metomi directory
    """
    if not path.exists(METOMI_DIR):
        mkdir(METOMI_DIR, 0o700)
    backup(METOMI_BASENAME)

ROSIE_ID_SECTION = 'rosie-id'
PREFIX_USERNAME_KEY = 'prefix-username.u'

def get_rose_username():
    """
    Get the MOSRS username from the Rosie configuration for prefix u
    """
    unable_message = 'Unable to retrieve MOSRS username from Rose config.'
    try:
        rose_config = Popen(
            ['rose', 'config', ROSIE_ID_SECTION, PREFIX_USERNAME_KEY],
            stdout=PIPE,
            stderr=PIPE)
        stdout, stderr = rose_config.communicate()
    except OSError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    if rose_config.returncode != 0:
        debug(unable_message)
        debug(stderr)
        return None
    return stdout.strip()

def save_rose_username(username):
    """
    Add the Rose username for prefix u to the Rose configuration file
    """
    debug('Saving MOSRS username "{}" to Rose config.'.format(username))
    # Backup the ~/.metomi directory
    backup_metomi()
    config_str = '[{}]\n{}={}'.format(
        ROSIE_ID_SECTION,
        PREFIX_USERNAME_KEY,
        username)
    unable_message = 'Unable to save MOSRS username to Rose config.'
    # Append the config string to the Rose configuration
    try:
        with open(METOMI_ROSE_CONF, 'a') as rose_conf_file:
            rose_conf_file.write(config_str)
    except IOError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError
    try:
        rose_config = Popen(
            ['rose', 'config', '--print-ignored', '--file', METOMI_ROSE_CONF],
            stdout=PIPE,
            stderr=PIPE)
        stdout, stderr = rose_config.communicate()
    except OSError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError
    stdout = '' if stdout is None else stdout
    stderr = '' if stderr is None else stderr
    if rose_config.returncode != 0:
        warning(unable_message)
        debug(stderr)
        raise AuthError
    # Write stdout to the Rose configuration
    try:
        with open(METOMI_ROSE_CONF, 'w') as rose_conf_file:
            rose_conf_file.write(stdout)
    except IOError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError

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
