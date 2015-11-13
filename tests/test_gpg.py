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

from mosrs.gpg import GPGAgent
import pytest

def test_store():
    gpg = GPGAgent()
    gpg.preset_passphrase('test:one','insecure')
    passwd = gpg.get_passphrase('test:one')
    assert passwd == 'insecure'

def test_clear():
    gpg = GPGAgent()
    gpg.preset_passphrase('test:one','insecure')
    gpg.clear_passphrase('test:one')
    with pytest.raises(Exception):
        passwd = gpg.get_passphrase('test:one')

