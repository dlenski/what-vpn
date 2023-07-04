#!/usr/bin/env python3

import sys
import os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

########################################

version_py = os.path.join('what_vpn', 'version.py')

d = {}
with open(version_py, 'r') as fh:
    exec(fh.read(), d)
    version_pep = d['__version__']

########################################

setup(
    name="what-vpn",
    version=version_pep,
    description="Identify servers running various SSL VPNs",
    long_description=open("README.md").read(),
    long_description_content_type='text/markdown',
    author="Daniel Lenski",
    author_email="dlenski@gmail.com",
    license='GPL v3 or later',
    python_requires=">=3",
    extras_require={
        "DTLS": [
            "python3-dtls @ https://github.com/mcfreis/pydtls/commits/py3",
        ]
    },
    install_requires=open("requirements.txt").readlines(),
    url="https://github.com/dlenski/what-vpn",
    packages=['what_vpn'],
    entry_points={'console_scripts': ['what-vpn=what_vpn.__main__:main']},
    test_suite='nose2.collector.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    ],
)
