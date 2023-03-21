#!/usr/bin/env python3
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

from datetime import date
from os import environ, getpid, makedirs, path
from shutil import rmtree
from subprocess import Popen, PIPE

from mosrs.encoding import communicate
from mosrs.exception import BackupError
from mosrs.message import debug, warning

def get_backup_path():
    """
    Define the path of the backup directory.
    Note: Since `date.today()` changes over time,
    this function should only be called once, at initialization time.
    """
    home = environ['HOME']
    backup_parent_name = '.mosrs-setup'
    backup_parent_path = path.join(home, backup_parent_name)
    today = date.today().isoformat()
    pid = getpid()
    backup_name = f'backup.{today}.{pid}'
    return path.join(backup_parent_path, backup_name)

BACKUP_PATH = get_backup_path()

def make_backup_dir(backup_path=BACKUP_PATH):
    """
    Make the backup directory
    """
    if not path.exists(backup_path):
        makedirs(backup_path, 0o700)
        debug(f'Created {backup_path}')
    return backup_path

def backup(path_name):
    """
    Backup a file or directory from the home directory.
    Note: The file or directory must exist and
    must be in the home directory itself, not a subdirectory.
    """
    # Check that the path is not in a subdirectory
    if path_name != path.basename(path_name):
        raise BackupError(f'Path contains a subdir: {path_name}')
    # Form the full path
    home = environ['HOME']
    full_path = path.join(home, path_name)
    # Check that the file or directory exists
    if not path.exists(full_path):
        raise BackupError(f'No such file or directory: {path_name}')
    # Make the backup directory
    backup_path = make_backup_dir()
    # Check that the backup does not already exist
    full_backup_path = path.join(backup_path, path_name)
    if not path.exists(full_backup_path):
        # Backup the file or directory
        debug(f'Backing up {path_name}.')
        with Popen(
            ['rsync', '-a', '--no-o', '--no-g', full_path, backup_path],
            stdout=PIPE,
            stderr=PIPE) as process:
            _ignore, stderr = communicate(process)
            if process.returncode != 0:
                # Backup failed. Try to clean up
                rmtree(full_backup_path, ignore_errors=True)
                warning(f'Backup via rsync failed: {stderr}')
                return False
    return True
