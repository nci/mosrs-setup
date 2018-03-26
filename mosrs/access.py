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

from . import gpg
from getpass import getpass
from hashlib import md5
import requests
import os

def main():
    passwd = getpass('Please enter your password for user %s: '%os.environ['USER'])

    # Test the password
    r = requests.get('https://access-svn.nci.org.au/svn/um',
            auth=(os.environ['USER'], passwd), verify=False)
    if r.status_code == 401:
        print('ERROR: Bad password for user %s'%os.environ['USER'])
        return
    r.raise_for_status()

    realm = '<https://access-svn.nci.org.au:443> AccessCollab'
    key = md5(realm).hexdigest()
    gpg.preset_passphrase(key, passwd)

    nemo_realm = '<https://access-svn.nci.org.au:443> nemo'
    nemo_key = md5(nemo_realm).hexdigest()
    gpg.preset_passphrase(nemo_key, passwd)

    realm = '<https://trac.nci.org.au:443> NCI Projects'
    key = md5(realm).hexdigest()
    gpg.preset_passphrase(key, passwd)

    print('SUCCESS: Password saved in gpg-agent for user %s'%os.environ['USER'])

if __name__ == '__main__':
    main()
