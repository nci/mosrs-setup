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
from mosrs.encoding import communicate, ENCODING
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
        with Popen(
            ['which', 'rose'],
            stdout=PIPE,
            stderr=PIPE) as command:
            _ignore, stderr = communicate(command)
            if command.returncode != 0:
                debug(f'{ROSE_UNABLE_MESSAGE} {stderr}')
            return command.returncode == 0
    except OSError as exc:
        raise AuthError(*(exc.args)) from exc

def check_rose():
    """
    Check the rose command
    """
    try:
        if not rose_is_found():
            raise AuthError
    except AuthError as exc:
        warning(ROSE_UNABLE_MESSAGE)
        todo('Please ensure that the correct modules are loaded.')
        raise AuthError from exc

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
        with Popen(
            ['rose', 'config', ROSIE_ID_SECTION, PREFIX_USERNAME_KEY],
            stdout=PIPE,
            stderr=PIPE) as rose_config:
            stdout, stderr = communicate(rose_config)
            if rose_config.returncode != 0:
                debug(unable_message)
                debug(stderr)
                return None
            return stdout.strip()
    except OSError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError from exc

def save_rose_username(username):
    """
    Add the Rose username for prefix u to the Rose configuration file
    """
    debug(f'Saving MOSRS username "{username}" to Rose config.')
    # Backup the ~/.metomi directory
    backup_metomi()
    unable_message = 'Unable to save MOSRS username to Rose config.'
    # Append the config string to the Rose configuration
    try:
        with open(METOMI_ROSE_CONF, 'a', encoding=ENCODING) as rose_conf_file:
            config_str = f'[{ROSIE_ID_SECTION}]\n{PREFIX_USERNAME_KEY}={username}'
            rose_conf_file.write(config_str)
    except IOError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError from exc
    try:
        with Popen(
            ['rose', 'config', '--print-ignored', '--file', METOMI_ROSE_CONF],
            stdout=PIPE,
            stderr=PIPE) as rose_config:
            stdout, stderr = communicate(rose_config)
            if rose_config.returncode != 0:
                warning(unable_message)
                debug(stderr)
                raise AuthError
    except OSError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError from exc
    # Write stdout to the Rose configuration
    try:
        with open(METOMI_ROSE_CONF, 'w', encoding=ENCODING) as rose_conf_file:
            rose_conf_file.write(stdout)
    except IOError as exc:
        warning(unable_message)
        for arg in exc.args:
            debug(arg)
        raise AuthError from exc

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
    with Popen(
        ['rosie', 'hello', f'--prefix={prefix}'],
        stdout=PIPE,
        stderr=PIPE) as process:
        stdout, stderr = communicate(process)
        unable_message = f'Unable to access rosie prefix {prefix} with your credentials:'
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
    todo(f'Check {PREFIX_USERNAME_KEY} in {METOMI_ROSE_CONF}.')
