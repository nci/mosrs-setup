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

from subprocess import Popen, PIPE, TimeoutExpired

from mosrs.message import debug

MOSRS_URL = 'https://code.metoffice.gov.uk'
MOSRS_TIMEOUT = 20

def is_connected():
    """
    Check that the network is connected
    """
    with Popen(
        ['wget', '-q', '-O', '/dev/null', MOSRS_URL],
        stdout=PIPE,
        stderr=PIPE) as process:
        try:
            process.communicate(timeout=MOSRS_TIMEOUT)
        except TimeoutExpired:
            process.kill()
            debug(f'wget {MOSRS_URL} timed out after {MOSRS_TIMEOUT} seconds.')
            return False
        connected = process.returncode == 0
        if not connected:
            debug(f'wget {MOSRS_URL} returned {process.returncode}.')
        return connected
