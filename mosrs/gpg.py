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

from subprocess import Popen, PIPE
from binascii import hexlify
from urllib import unquote
from os import environ

from mosrs.message import debug

class GPGError(Exception):
    """
    Indicates an anticipated error
    """
    pass

def get_passphrase(cache_id):
    """
    Get a passphrase from the cache

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
    """
    stdout = send("GET_PASSPHRASE --no-ask --data {} X X X\n".format(cache_id))
    try:
        result = unquote(stdout[0][2:])
    except IndexError:
        if stdout:
            debug('get_passphrase: IndexError: len(stdout[0]) == {}'.format(len(stdout[0])))
        else:
            debug('get_passphrase: IndexError: stdout is empty')
        raise GPGError('get_passphrase:', 'IndexError')
    return result

def clear_passphrase(cache_id):
    """
    Remove a passphrase from the cache

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
    """
    send("CLEAR_PASSPHRASE {}\n".format(cache_id))

def preset_passphrase(keygrip, passphrase):
    """
    Add a passphrase to the cache for `keygrip`

    https://www.gnupg.org/documentation/manuals/gnupg/Agent-PRESET_005fPASSPHRASE.html
    """
    # Only -1 is allowed for timeout
    timeout = -1
    assert passphrase is not None
    send("PRESET_PASSPHRASE {} {} {}\n".format(keygrip, timeout, hexlify(passphrase)))

def send(message):
    """
    Connect to the agent and send a message
    """
    agent = Popen(
        ['gpg-connect-agent'],
        bufsize=0,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE)
    stdout, stderr = agent.communicate(message)
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
    if result != "OK":
        raise GPGError('gpg.check_return:', result)

def set_environ():
    """
    Setup the assumed environment variables GPG_TTY and GPG_AGENT_INFO
    """
    process = Popen(
        ['tty'],
        stdout=PIPE,
        stderr=PIPE)
    stdout, _stderr = process.communicate()
    if process.returncode == 0:
        stdout_line = stdout.splitlines()[0]
        environ['GPG_TTY'] = stdout_line
    process = Popen(
        ['gpgconf', '--list-dirs', 'agent-socket'],
        stdout=PIPE,
        stderr=PIPE)
    stdout, _stderr = process.communicate()
    if process.returncode == 0:
        stdout_line = stdout.splitlines()[0]
        environ['GPG_AGENT_INFO'] = stdout_line + ':0:1'

def start_gpg_agent():
    """
    Make sure that the agent is running
    """
    send('GETINFO version')
    set_environ()
