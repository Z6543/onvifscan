#!/usr/bin/env python3
"""
Setup script for ONVIF Security Scanner
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding='utf-8') as f:
        return f.read()

setup(
    name='onvifscan',
    version='1.0.0',
    description='ONVIF Security Scanner - Security testing tools for ONVIF devices',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='Brown Fine Security',
    author_email='',
    url='https://github.com/BrownFineSecurity/onvifscan',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'onvifscan': [],
        '': ['wordlists/*.txt'],
    },
    data_files=[
        ('wordlists', ['wordlists/onvif-usernames.txt', 'wordlists/onvif-passwords.txt']),
    ],
    scripts=[
        'bin/onvifscan',
        'bin/wsdiscovery',
    ],
    install_requires=[
        'requests>=2.25.0',
        'colorama>=0.4.4',
    ],
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Networking',
    ],
    keywords='onvif security scanner camera iot pentest wsdiscovery',
    project_urls={
        'Bug Reports': 'https://github.com/BrownFineSecurity/onvifscan/issues',
        'Source': 'https://github.com/BrownFineSecurity/onvifscan',
    },
)
