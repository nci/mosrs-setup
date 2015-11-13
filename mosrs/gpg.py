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

def _e(string):
    """
    Percent-escape a string
    """
    return urllib.quote(string)

class GPGAgentConnection:
    def __init__(self):
        self.agent = Popen(['gpg-connect-agent'],
                stdout = PIPE,
                stderr = PIPE,
                stdin  = PIPE,
                )

    def get_passphrase(self, cache_id):
        """
        Get a passphrase from the cache

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
        """
        self.agent.stdin.write("GET_PASSPHRASE --data %s"%_e(cache_id))
        self._check_return()
        return self.stdout.readline()

    def clear_passphrase(self, cache_id):
        """
        Remove a passphrase from the cache

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-GET_005fPASSPHRASE.html
        """
        self.agent.stdin.write("CLEAR_PASSPHRASE %s"%_e(cache_id))
        self._check_return()

    def preset_passphrase(self, keygrip, passphrase=None):
        """
        Add a passphrase to the cache for `keygrip`

        https://www.gnupg.org/documentation/manuals/gnupg/Agent-PRESET_005fPASSPHRASE.html
        """
        # Only -1 is allowed for timeout
        timeout = -1
        if passphrase is not None:
            self.agent.stdin.write("PRESET_PASSPHRASE %s %s %s"%(_e(keygrip), _e(timeout), _e(passphrase)))
        else:
            self.agent.stdin.write("PRESET_PASSPHRASE %s %s"%(_e(keygrip), _e(timeout)))

        self._check_return()

    def _check_return(self):
        line = self.stdout.readline()
        if line != "OK":
            raise Exception(line)

    def close(self):
        # Wait for the connection to finish
        self.agent.communicate()

    def __enter__(self):
        return self
    def __exit__(self):
        self.close()

