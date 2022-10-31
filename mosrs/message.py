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

debugging = False # pylint: disable=C0103

class MessageError(Exception):
    """
    Indicates an anticipated error
    """
    pass

def colour(text, colour_name):
    """
    Return the ANSI colour escape sequence for a named colour
    """
    if colour_name == 'red':
        code = '\033[91m'
    elif colour_name == 'green':
        code = '\033[32m'
    elif colour_name == 'blue':
        code = '\033[94m'
    elif colour_name == 'magenta':
        code = '\033[95m'
    else:
        raise MessageError('Unimplemented colour:', colour)
    reset = '\033[m'
    return code + text + reset

def debug(text):
    """
    Print a debug message
    """
    if debugging:
        print('{}: {}'.format(colour('DBUG', 'magenta'), text))

def info(text):
    """
    Print an information message
    """
    print('{}: {}'.format(colour('INFO', 'blue'), text))

def todo(text):
    """
    Print a todo message
    """
    print('{}: {}'.format(colour('TODO', 'green'), text))

def warning(text):
    """
    Print a warning message
    """
    print('{}: {}'.format(colour('WARN', 'red'), text))
