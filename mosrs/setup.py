#!/usr/bin/env python
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

from __future__ import print_function
from subprocess import Popen, PIPE
from textwrap import dedent
from os import environ, path
from distutils.util import strtobool
import ldap
import getpass
import socket

from . import auth, gpg

def colour(text, colour):
    if colour == 'red':
        code = '\033[31;1m'
    elif colour == 'green':
        code = '\033[32m'
    elif colour == 'blue':
        code = '\033[93m'
    else:
        raise Exception
    reset = '\033[m'
    return code + text + reset

def info(text):
    print("%s: %s"%(colour('INFO','blue'),text))
def warning(text):
    print("%s: %s"%(colour('WARN','red'),text))
def todo(text):
    print("%s: %s"%(colour('TODO','green'),text))

class SetupError(Exception):
    """
    Indicates user needs to take action before setup can complete
    """
    pass

def userinfo():
    """
    Get current user's common name and email from LDAP

    Returns: Tuple of (name, email)
    """
    l = ldap.initialize(ldap.get_option(ldap.OPT_URI))
    people = 'ou=People,dc=apac,dc=edu,dc=au'
    info = l.search_s(people, ldap.SCOPE_SUBTREE, '(uid=%s)'%getpass.getuser())

    return (info[0][1]['cn'][0],info[0][1]['mail'][0])

def prompt_bool(prompt):
    """
    Ask a yes/no question

    Returns: true/false answer
    """
    raw_value = raw_input(prompt + ' [yes/no] ')
    try:
        return strtobool(raw_value)
    except ValueError:
        return ask_bool(prompt)

def prompt_or_default(prompt, default):
    """
    Ask a question with a default answer

    Returns: answer or default
    """
    response = raw_input('%s [%s]: '%(prompt,default)).strip()
    if response == '':
        response = default
    return response

def gpg_startup():
    agent = dedent("""
    if gpg-agent --use-standard-socket-p; then
        # New GPG always returns 0. Restart the agent
        gpg-connect-agent reloadagent /bye
        export GPG_TTY=$(tty)
        export GPG_AGENT_INFO=$HOME/.gnupg/S.gpg-agent:0:1
    else
        # Old GPG
        [ -f ~/.gpg-agent-info ] && source ~/.gpg-agent-info
        if [ -S "${GPG_AGENT_INFO%%:*}" ]; then
            export GPG_AGENT_INFO
        else
            eval $( gpg-agent --daemon --allow-preset-passphrase --batch --max-cache-ttl 43200 --write-env-file ~/.gpg-agent-info )
        fi
    fi
    """)
    home = environ['HOME']
    for f in ['.profile','.bash_profile']:
        p = path.join(home,f)
        if path.exists(p):
            # Check if gpg-agent is already referenced
            grep = Popen(['grep','gpg-agent',p],stdout=PIPE)
            grep.communicate()
            if grep.returncode == 0:
                warning('GPG Agent is referenced in ~/%s but is not currently running. '%f+
                        'Try relogging to start it again, if that doesn\'t work please contact the helpdesk')
                continue

            # Add script to file
            with open(p,'a') as profile:
                profile.write(agent)

    host = "OOD" if on_ood() else "Accessdev"
    todo('GPG Agent has been added to your startup scripts. '+
            'Please log out of ' + host +
            ' then back in again to make sure it has been activated\n')


def check_gpg_agent():
    """
    Make sure GPG-Agent is running

    If the environment variable is not found add activation script to the
    users's .profile
    """
    try:
        gpg.send('GETINFO version')
        info('GPG Agent is running')
    except Exception:
        gpg_startup()
        raise SetupError

def register_mosrs_account():
    name, email = userinfo()
    name  = prompt_or_default('What is your name?',name)
    email = prompt_or_default('What is your work email address?',email)
    request = Popen(['mail', '-s','MOSRS account request for %s'%name, 'access_help@nf.nci.org.au'], stdin=PIPE)
    request.communicate(dedent("""
            ACCESS user %s (NCI id %s, email <%s>) would like to request an account on MOSRS.
            Can the sponsor for their institution please submit a request on their behalf at
                https://code.metoffice.gov.uk/trac/admin/newticket?type=account-request

            You can check if they have an existing account at
                https://code.metoffice.gov.uk/trac/home/wiki/UserList
            """%(name, environ['USER'], email)))
    print('\n')
    info('Submitting MOSRS account request for %s <%s> to access_help'%(name,email))
    info('Once your account has been activated (will take at least one UK business day) '+
            'you will receive an email detailing how to set up your password\n')

def setup_mosrs_account():
    """
    Setup Mosrs
    """
    check_gpg_agent()
    mosrs_request = None
    while mosrs_request not in ['yes', 'no', 'y', 'n']:
        mosrs_request = prompt_or_default("Do you have a MOSRS account", "yes")
        mosrs_request = mosrs_request.lower()
    if mosrs_request.startswith('y'):
        auth.check_or_update()
    else:
        print(dedent(
            """
            If you need to access new versions of the UM please send a
            request to 'cws_help@nci.org.au' saying that you'd like a MOSRS account

            Once you have an account run this script again
            """
        ))
    print('\n')

def check_raijin_ssh():
    """
    Raijin has been decommissioned. There should no longer be any calls to this
    procedure. In case there is, I'm leaving this stub in.
    """
    raise ValueError("raijin should no longer be used. Please contact CMS")

def check_gadi_ssh():
    """
    Test Rose/Cylc can be found on Gadi
    """
    print('Testing Rose can be accessed on Gadi...')
    # ssh -oBatchMode=yes /projects/access/bin/cylc --version
    ssh = Popen(['ssh','-oBatchMode=yes','gadi','/projects/access/bin/cylc --version'])
    result = ssh.wait()
    if result == 0:
        print('Successfully found Rose\n')
    else:
        warning('Unable to connect to Gadi')
        warning('Follow the instructions at https://accessdev.nci.org.au/trac/wiki/Guides/SSH to set up a SSH agent\n')
        raise SetupError

def accesssvn_setup():
    """
    Setup GPG for access-svn access
    """
    try:
        check_gpg_agent()
        print('\n')
        print('To store your password for 12 hours run:')
        print('    access-auth\n')
    except SetupError:
        todo('Once this has been done please run this setup script again\n')

def on_ood():
    hostname = socket.gethostname()
    return hostname.startswith("ood")

def main():
    print('\n')
    if on_ood():
        print('Welcome to OOD, the NCI Open OnDemand service')
    else:
        print('Welcome to Accessdev, the user interface and control server for the ACCESS model at NCI')
    print('This script will set up your account to use Rose and the UM\n')

    try:
        setup_mosrs_account()

        if not on_ood():
            check_gadi_ssh()

        # Account successfully created
        print('You are now able to use Rose and the UM. To see a list of available experiments run:')
        print('    rosie go\n')
        print('Your password will be cached for a maximum of 12 hours. To store your password again run:')
        print('    mosrs-auth\n')
    except SetupError:
        todo('Once this has been done please run this setup script again\n')
    finally:
        print('You can ask for help with the ACCESS systems by emailing "access_help@nf.nci.org.au"\n')

if __name__ == '__main__':
    main()
