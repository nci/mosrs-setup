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

from mosrs.message import debug

MOSRS_URL = 'https://code.metoffice.gov.uk'

def is_connected():
    """
    Check that the network is connected
    """
    process = Popen(
        ['wget', '-q', '-O', '/dev/null', MOSRS_URL],
        stdout=PIPE,
        stderr=PIPE)
    process.communicate()
    if process.returncode != 0:
        debug('wget {} returned {}'.format(MOSRS_URL, process.returncode))
    return process.returncode == 0
