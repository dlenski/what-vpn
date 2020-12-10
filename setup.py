#!/usr/bin/env python3

import sys, os
try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

if not sys.version_info[0] == 3:
    sys.exit("Python 2.x is not supported; Python 3.x is required.")

########################################

version_py = os.path.join('what_vpn', 'version.py')

d = {}
with open(version_py, 'r') as fh:
    exec(fh.read(), d)
    version_pep = d['__version__']

########################################

setup(name="what-vpn",
      version=version_pep,
      description="Identify servers running various SSL VPNs",
      long_description=open("description.rst").read(),
      author="Daniel Lenski",
      author_email="dlenski@gmail.com",
      license='GPL v3 or later',
      install_requires=[ 'requests>=2.0.0' ],
      url="https://github.com/dlenski/what-vpn",
      packages = ['what_vpn'],
      entry_points={ 'console_scripts': [ 'what-vpn=what_vpn.__main__:main' ] },
      tests_require=['nose>=1.0'],
      test_suite='nose.collector',
      )
