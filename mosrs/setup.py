#!/usr/bin/env python2
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
from os import environ, rename, path
from distutils.util import strtobool
import ldap
import getpass
import socket

from . import auth, gpg, host, message
from host import get_host, on_accessdev
from message import info, warning, todo

class SetupError(Exception):
    """
    Indicates user needs to take action before setup can complete
    """
    pass

def prompt_or_default(prompt, default):
    """
    Ask a question with a default answer

    Returns: answer or default
    """
    response = raw_input('{} [{}]: '.format(prompt,default)).strip()
    if response == '':
        response = default
    return response

def gpg_startup(gpg_environ):
    gpg_agent_script = dedent("""
    # mosrs-setup gpg_agent_script: DO NOT EDIT BETWEEN HERE AND END
    function export_gpg_environ {
        export GPG_TTY=$(tty)
        export GPG_AGENT_INFO="$(gpgconf --list-dirs agent-socket):0:1"
    }
    function start_gpg_agent {
        mkdir -p $HOME/.gnupg
        gpg-connect-agent /bye
        export_gpg_environ
    }
    if in_interactive_shell; then
        if in_login_shell; then
            start_gpg_agent
        fi
    fi
    # mosrs-setup gpg_agent_script: END

    """)
    home = environ['HOME']
    f = '.bashrc'
    p = path.join(home,f)
    if not path.exists(p):
        warning('Startup script ~/{} does not exist'.format(f))
        todo('Please contact the helpdesk.')
        raise SetupError
    else:
        # Check if gpg-connect-agent is already referenced
        grep_gpg_agent_script = Popen(['grep','mosrs-setup gpg_agent_script',p],
                                stdout=PIPE)
        grep_gpg_agent_script.communicate()
        if grep_gpg_agent_script.returncode == 0:
            if gpg_environ is not None:
                return
            else:
                warning(
                    'Startup script ~/{} contains gpg_agent_script but '.format(f) +
                    'GPG environment variables are not defined.')
                todo('Please log out of {} then back in again '.format(get_host()) +
                     'to check that GPG environment variables are defined.')
                todo('If that doesn\'t work please contact the helpdesk.')
                raise SetupError

        # Look for NCI boilerplate in startup file
        boilerplate = 'if in_interactive_shell; then'
        grep_boilerplate = Popen(['grep',boilerplate,p],
                           stdout=PIPE)
        grep_boilerplate.communicate()
        if grep_boilerplate.returncode == 0:
            # Boilerplate has been found
            old_f = f + '.old'
            old_p = path.join(home,old_f)
            rename(p,old_p)
            with open(old_p,'r') as old_startup_file:
                old = old_startup_file.read()
                insert_here = old.find(boilerplate)
                new = old[:insert_here] + gpg_agent_script + old[insert_here:]
                with open(p,'w') as startup_file:
                    startup_file.write(new)
        else:
            # Append gpg_agent_script to file
            with open(p,'a') as startup_file:
                startup_file.write(gpg_agent_script)

    todo('GPG Agent has been added to your startup script. ' +
         'Please log out of {} then back in again '.format(get_host()) +
         'to make sure it has been activated.')
    raise SetupError

def check_gpg_startup():
    """
    Check that GPG environment variables are defined
    and add GPG agent to startup if needed.
    """
    gpg_environ = None
    try:
        gpg_environ = gpg.get_environ()
    except KeyError:
        pass
    gpg_startup(gpg_environ)

def start_gpg_agent():
    """
    Start the GPG agent if it has not already started
    """
    try:
        gpg.start_gpg_agent()
    except gpg.GPGError as e:
        warning('GPGError in gpg.start_gpg_agent')
        info(e.result)
        raise SetupError
    except Exception as e:
        warning('Exception in gpg.start_gpg_agent')
        for arg in e.args:
            info(e)
        raise SetupError

def setup_mosrs_account():
    """
    Setup MOSRS
    """
    check_gpg_startup()
    start_gpg_agent()
    # Save account details and cache credentials
    mosrs_request = None
    while mosrs_request not in ['yes', 'no', 'y', 'n']:
        mosrs_request = prompt_or_default("Do you have a MOSRS account", "yes")
        mosrs_request = mosrs_request.lower()
    if mosrs_request.startswith('y'):
        try:
            auth.check_or_update()
        except Exception as e:
            warning('Authentication check and update failed.')
            for arg in e.args:
                info(e)
            todo(dedent(
                """
                Please check your credentials. If you have recently reset your password
                it may take a bit of time for the server to recognise the new password.
                """
            ))
            raise SetupError
    else:
        todo(dedent(
            """
            Please send a request for a MOSRS account to your MOSRS Group Sponsor,
            copying in the Lead Chief Investigator of your NCI project.
            See https://my.nci.org.au for information on your project.
            """
        ))
        raise SetupError

def main():
    print()
    if on_accessdev():
        warning('This version of mosrs-setup is not intended to run on accessdev.')
        return
    print('This script will set up your account to use Rose and the MOSRS Subversion repositories\n')

    try:
        setup_mosrs_account()

        # Account successfully created
        print()
        info('You are now able to use Rose and the MOSRS Subversion repositories. To see a list of available experiments run:')
        print('    rosie go\n')
        info('Your password will be cached for a maximum of 12 hours. To store your password again run:')
        print('    mosrs-auth\n')
    except SetupError:
        todo('Once this has been done please run this setup script again.')
    except Exception as e:
        warning('Unexpected exception in mosrs-setup:')
        for arg in e.args:
            info(e)
    finally:
        info('You can ask for help with the ACCESS systems by emailing "help@nci.org.au"\n')

if __name__ == '__main__':
    main()
