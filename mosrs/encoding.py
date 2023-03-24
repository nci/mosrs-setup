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

ENCODING = 'UTF-8'

def decode(bytes_obj):
    """
    Decode a bytes object using ENCODING
    """
    return (
        '' if bytes_obj is None else
        bytes_obj.decode(ENCODING))

def communicate(process, message=None):
    """
    Decode the results of process.communicate using ENCODING
    """
    message_bytes = None if message is None else message.encode()
    stdout_bytes, stderr_bytes = process.communicate(message_bytes)
    stdout = decode(stdout_bytes)
    stderr = decode(stderr_bytes)
    return stdout, stderr
