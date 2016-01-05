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
from os import environ
from distutils.util import strtobool

class SetupError(Exception):
    pass

def gpg_agent():
    """
    Make sure GPG-Agent is running

    If the environment variable is not found add activation script to the
    users's .profile
    """
    if 'GPG_AGENT_INFO' not in environ:
        print('GPG Agent not found, adding to startup scripts')
        agent = dedent("""
            [ -f ~/.gpg-agent-info ] && source ~/.gpg-agent-info
            if [ -S "${GPG_AGENT_INFO%%:*}" ]; then
                export GPG_AGENT_INFO
            else
                eval $( gpg-agent --daemon --allow-preset-passphrase --batch --max-cache-ttl 43200 --write-env-file ~/.gpg-agent-info )
            fi
            """)
        with open('~/.bash_profile','a') as profile:
            profile.write(agent)
        with open('~/.profile','a') as profile:
            profile.write(agent)
        print('GPG agent has been added to your startup scripts. Please log out of Accessdev then back in again to make sure it has been activated\n')
        raise SetupError
    print('GPG Agent is running')

def ask_bool(prompt):
    raw_value = raw_input(prompt)
    try:
        return strtobool(raw_value)
    except ValueError:
        return ask_bool(prompt)


def mosrs_account():
    """
    Setup Mosrs
    """
    registered = ask_bool('Do you have an existing account on https://code.metoffice.gov.uk? [yes/no]')
    if not registered:
        name  = raw_input('What is your name?')
        email = raw_input('What is your work email address?')
        request = Popen(['mail',
                            '-s','MOSRS account request for %s'%name,
                            'saw562@nci.org.au'],
                        stdin=PIPE)
        request.communicate("%s (NCI id %s, email <%s>) would like to request an account on MOSRS. Can the sponsor for their institution please submit a request on their behalf at https://code.metoffice.gov.uk/trac/admin/newticket?type=account-request"%(name, environ['USER'], email))
        print('Submitting MOSRS account request for %s <%s> to access_help'%(name,email))
        print('Once your account has been activated (will take at least one UK business day) you will receive an email detailling how to set up your password\n')
        raise SetupError

    gpg_agent()

def raijin_ssh():
    """
    Test Cylc can be found on Raijin
    """
    print('Testing Rose can be accessed on Raijin...')
    # ssh -oBatchMode=yes /projects/access/bin/cylc --version
    ssh = Popen(['ssh','-oBatchMode=yes','raijin','/projects/access/bin/cylc --version'])
    result = ssh.wait()
    if result == 0:
        print('Successfully found Rose\n')
    else:
        print('Unable to connect to Raijin')
        print('Follow the instructions at https://accessdev.nci.org.au/trac/wiki/guides/SSH to set up a SSH agent\n')
        raise SetupError

def main():
    print('Welcome to Accessdev, the user interface and control server for the ACCESS model at NCI')
    print('This script will set up your account to use Rose and the UM\n')
    
    try:
        mosrs_account()
        raijin_ssh()

        print('You are now able to use Rose and the UM. To see a list of available experiments run:')
        print('    rosie go\n')
    except SetupError:
        print('Once this is done please run this setup script again')
    finally:
        print('You can ask for help with the ACCESS systems by emailing "access_help@nf.nci.org.au"')
    


if __name__ == '__main__':
    main()
