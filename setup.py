"""Installs iodeflib using distutils

Run:
    python setup.py install

to install this package.

(setup script borrowed from cherrypy)
"""

##try:
##    from setuptools import setup
##except ImportError:
from distutils.core import setup

from distutils.command.install import INSTALL_SCHEMES
import sys
import os
import iodeflib

###############################################################################
# arguments for the setup command
###############################################################################
name = "iodeflib"
version = iodeflib.__version__
desc = "a python library to create, parse and edit cyber incident reports using the IODEF XML format (RFC 5070)"
long_desc = open('iodeflib/README.txt').read()
classifiers=[
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: BSD License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2",
#    "Programming Language :: Python :: 3",
    "Topic :: Security",
]
author="Philippe Lagadec"
author_email="decalage at laposte dot net"
url="http://www.decalage.info/python/iodeflib"
license="BSD"
packages=[
    "iodeflib", 'iodeflib.examples',
]
download_url="https://bitbucket.org/decalage/iodeflib/downloads"
data_files=[
    ('iodeflib', [
        'iodeflib/README.txt',
        'iodeflib/iodef-1.0.xsd',
                  ]),
    ('iodeflib.examples', [
        'iodeflib/examples/iodef.xml',
                  ]),
]
##if sys.version_info >= (3, 0):
##    required_python_version = '3.0'
##    setupdir = 'py3'
##else:
##    required_python_version = '2.3'
##    setupdir = 'py2'
setupdir = '.'
package_dir={'': setupdir}
##data_files = [(install_dir, ['%s/%s' % (setupdir, f) for f in files])
##              for install_dir, files in data_files]
#scripts = ["%s/cherrypy/cherryd" % setupdir]

###############################################################################
# end arguments for setup
###############################################################################

##def fix_data_files(data_files):
##    """
##    bdist_wininst seems to have a bug about where it installs data files.
##    I found a fix the django team used to work around the problem at
##    http://code.djangoproject.com/changeset/8313 .  This function
##    re-implements that solution.
##    Also see http://mail.python.org/pipermail/distutils-sig/2004-August/004134.html
##    for more info.
##    """
##    def fix_dest_path(path):
##        return '\\PURELIB\\%(path)s' % vars()
##
##    if not 'bdist_wininst' in sys.argv: return
##
##    data_files[:] = [
##        (fix_dest_path(path), files)
##        for path, files in data_files]
##fix_data_files(data_files)

def main():
##    if sys.version < required_python_version:
##        s = "I'm sorry, but %s %s requires Python %s or later."
##        print(s % (name, version, required_python_version))
##        sys.exit(1)
##    # set default location for "data_files" to
##    # platform specific "site-packages" location
##    for scheme in list(INSTALL_SCHEMES.values()):
##        scheme['data'] = scheme['purelib']

    dist = setup(
        name=name,
        version=version,
        description=desc,
        long_description=long_desc,
        classifiers=classifiers,
        author=author,
        author_email=author_email,
        url=url,
        license=license,
        package_dir=package_dir,
        packages=packages,
        download_url=download_url,
        data_files=data_files,
#        scripts=scripts,
    )


if __name__ == "__main__":
    main()
