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
from urllib.parse import unquote

from mosrs.backup import backup
from mosrs.encoding import communicate, ENCODING
from mosrs.exception import GPGError
from mosrs.message import debug

def get_passphrase(cache_id):
    """
    Get a passphrase from the cache

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
    """
    stdout = send('GET_PASSPHRASE --no-ask --data {} X X X\n'.format(cache_id))
    try:
        result = unquote(stdout[0][2:])
    except IndexError as exc:
        index_error_str = 'get_passphrase: IndexError'
        if stdout:
            debug(index_error_str + ': len(stdout[0]) == {}'.format(len(stdout[0])))
        else:
            debug(index_error_str + ': stdout is empty.')
        raise GPGError(index_error_str) from exc
    return result

def clear_passphrase(cache_id):
    """
    Remove a passphrase from the cache

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
    """
    send('CLEAR_PASSPHRASE {}\n'.format(cache_id))

def preset_passphrase(keygrip, passphrase):
    """
    Add a passphrase to the cache for `keygrip`

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-PRESET_005fPASSPHRASE.html
    """
    # Only -1 is allowed for timeout
    timeout = -1
    hex_passphrase = passphrase.encode().hex()
    send('PRESET_PASSPHRASE {} {} {}\n'.format(
        keygrip,
        timeout,
        hex_passphrase))

def send(message):
    """
    Connect to the agent and send a message
    """
    with Popen(
        ['gpg-connect-agent'],
        bufsize=0,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE) as agent:
        stdout, stderr = communicate(agent, message)
        if agent.returncode != 0:
            raise GPGError(
                'gpg.send:',
                'Could not connect to gpg-agent:\n{}'.format(stderr))
        check_return(stdout)
        return stdout.split('\n')[0:-2]

def check_return(stdout):
    """
    Check status returned on last line
    """
    result = stdout.split('\n')[-2]
    if result != 'OK':
        raise GPGError('gpg.check_return:', result)

def set_environ():
    """
    Setup the assumed environment variables GPG_TTY and GPG_AGENT_INFO
    """
    with Popen(
        ['tty'],
        stdout=PIPE,
        stderr=PIPE) as process:
        stdout, _ignore = communicate(process)
        if process.returncode == 0:
            stdout_line = stdout.splitlines()[0]
            environ['GPG_TTY'] = stdout_line
    with Popen(
        ['gpgconf', '--list-dirs', 'agent-socket'],
        stdout=PIPE,
        stderr=PIPE) as process:
        stdout, _ignore = communicate(process)
        if process.returncode == 0:
            stdout_line = stdout.splitlines()[0]
            environ['GPG_AGENT_INFO'] = stdout_line + ':0:1'

GNUPG_BASENAME = '.gnupg'
GNUPG_DIR = path.join(environ['HOME'], GNUPG_BASENAME)

def backup_gnupg():
    """
    Backup the ~/.gnupg directory
    """
    if not path.exists(GNUPG_DIR):
        mkdir(GNUPG_DIR, 0o700)
    backup(GNUPG_BASENAME)

def mkdir_gnupg():
    """
    Create the ~/.gnupg directory if it does not exist
    """
    if not path.exists(GNUPG_DIR):
        mkdir(GNUPG_DIR, 0o700)

def check_gpg_agent_conf():
    """
    Check the user's GPG agent configuration and append any missing lines
    """
    conf_updated = False
    gpg_agent_conf_allow_preset_passphrase = 'allow-preset-passphrase'
    gpg_agent_conf_max_cache_ttl = 'max-cache-ttl 43200'

    # Create the ~/.gnupg directory if it does not exist
    mkdir_gnupg()
    gpg_agent_conf_name = 'gpg-agent.conf'
    gpg_agent_conf_path = path.join(GNUPG_DIR, gpg_agent_conf_name)
    if not path.exists(gpg_agent_conf_path):
        # Backup the ~/.gnupg directory
        backup_gnupg()
        with open(gpg_agent_conf_path, 'w', encoding=ENCODING) as gpg_agent_conf_file:
            gpg_agent_conf_file.write(gpg_agent_conf_allow_preset_passphrase + '\n')
            gpg_agent_conf_file.write(gpg_agent_conf_max_cache_ttl + '\n')
        conf_updated = True
        debug('Created {}'.format(gpg_agent_conf_path))
    else:
        # Check if gpg_agent.conf contains the line 'allow-preset-passphrase'
        debug('Checking {}'.format(gpg_agent_conf_path))
        with Popen(
            ['grep', gpg_agent_conf_allow_preset_passphrase, gpg_agent_conf_path],
            stdout=PIPE) as grep_command:
            grep_command.communicate()
            if grep_command.returncode != 0:
                # Backup the ~/.gnupg directory
                backup_gnupg()
                with open(gpg_agent_conf_path, 'a', encoding=ENCODING) as gpg_agent_conf_file:
                    gpg_agent_conf_file.write(gpg_agent_conf_allow_preset_passphrase + '\n')
                conf_updated = True
                debug('Updated {}'.format(gpg_agent_conf_path))
        # Check if gpg_agent.conf contains the line 'max-cache-ttl 43200'
        with Popen(
            ['grep', gpg_agent_conf_max_cache_ttl, gpg_agent_conf_path],
            stdout=PIPE) as grep_command:
            grep_command.communicate()
            if grep_command.returncode != 0:
                # Backup the ~/.gnupg directory
                backup_gnupg()
                with open(gpg_agent_conf_path, 'a', encoding=ENCODING) as gpg_agent_conf_file:
                    gpg_agent_conf_file.write(gpg_agent_conf_max_cache_ttl + '\n')
                conf_updated = True
                debug('Updated {}'.format(gpg_agent_conf_path))
    return conf_updated

def start_gpg_agent():
    """
    Make sure that the agent is running
    """
    conf_updated = check_gpg_agent_conf()
    command = (
        'RELOADAGENT' if conf_updated else
        'GETINFO version')
    send(command)
    set_environ()
