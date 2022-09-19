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

def colour(text, colour):
    if colour == 'red':
        code = '\033[31;1m'
    elif colour == 'green':
        code = '\033[32m'
    elif colour == 'blue':
        code = '\033[93m'
    else:
        raise Exception
    reset = '\033[m'
    return code + text + reset

def info(text):
    print("%s: %s"%(colour('INFO','blue'),text))
def warning(text):
    print("%s: %s"%(colour('WARN','red'),text))
def todo(text):
    print("%s: %s"%(colour('TODO','green'),text))
    
