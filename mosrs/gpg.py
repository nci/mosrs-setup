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

from __future__ import print_function

from subprocess import Popen, PIPE
from urllib import quote as _e
from binascii import hexlify

class GPGAgent:
    def get_passphrase(self, cache_id):
        """
        Get a passphrase from the cache

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
        """
        stdout = self.send("GET_PASSPHRASE --data %s X X X\n"%_e(cache_id))
        return stdout[0][2:]

    def clear_passphrase(self, cache_id):
        """
        Remove a passphrase from the cache

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
        """
        self.send("CLEAR_PASSPHRASE %s\n"%_e(cache_id))

    def preset_passphrase(self, keygrip, passphrase=None):
        """
        Add a passphrase to the cache for `keygrip`

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-PRESET_005fPASSPHRASE.html
        """
        # Only -1 is allowed for timeout
        timeout = -1
        if passphrase is not None:
            self.send("PRESET_PASSPHRASE %s %s %s\n"%(_e(keygrip), timeout, hexlify(passphrase)))
        else:
            self.send("PRESET_PASSPHRASE %s %s\n"%(_e(keygrip), timeout))

    def send(self, string):
        agent = Popen(['gpg-connect-agent'],
                bufsize = 0,
                stdout = PIPE,
                stdin  = PIPE,
                )
        stdout, stderr = agent.communicate(string)
        _check_return(string,stdout)
        return stdout.split('\n')[0:-2]

def _check_return(string,stdout):
    line = stdout.split('\n')[-2]
    if line != "OK":
        raise Exception(string,line)

