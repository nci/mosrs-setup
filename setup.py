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

from setuptools import setup, find_packages

setup(
    name='mosrs',
    version='0.9.11',
    description='Cache credentials for NCI users of MOSRS',
    license='Apache License, Version 2.0',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    author='Scott Wales',
    maintainer='National Computational Infrastructure',
    install_requires=[
        'python-ldap <= 3.3.1',
        'certifi <= 2021.10.8',
        'requests < 2.28',
        ],
    entry_points={
        'console_scripts': [
            'mosrs-auth=mosrs.auth:main',
            'mosrs-setup=mosrs.setup:main',
            ]
        }
    )
