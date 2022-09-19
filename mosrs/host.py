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

import socket

def get_host():
    hostname = socket.gethostname()
    for name in [
            "accessdev",
            "gadi-login",
            "ood"]:
        if name in hostname:
            return name
    for name in [
            "gadi-analysis",
            "gadi-dm",
            ]:
        if name in hostname:
            return "ARE"
    return "unsupported"

def on_accessdev():
    hostname = get_host()
    return hostname == "accessdev"

def on_ood():
    hostname = get_host()
    return hostname == "ood"

