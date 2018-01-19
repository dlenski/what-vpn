#!/usr/bin/env python3

import sys
from setuptools import setup

if not sys.version_info[0] == 3:
    sys.exit("Python 2.x is not supported; Python 3.x is required.")

setup(name="what-vpn",
      version="0.0.1",
      description="Identify servers running various SSL VPNs",
      long_description=open("README.md").read(),
      author="Daniel Lenski",
      author_email="dlenski@gmail.com",
      license='GPL v3 or later',
      install_requires=[ 'requests>=2.0.0' ],
      url="https://github.com/dlenski/what-vpn",
      packages = ['what_vpn'],
      entry_points={ 'console_scripts': [ 'what-vpn=what_vpn.__main__:main' ] },
      test_suite='nose.collector',
      )
