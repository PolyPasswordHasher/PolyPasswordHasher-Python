#! /usr/bin/env python
from __future__ import with_statement

import sys
try:
    from setuptools import setup, Extension, Command
except ImportError:
    from distutils.core import setup, Extension, Command
from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError, DistutilsExecError, \
    DistutilsPlatformError

IS_PYPY = hasattr(sys, 'pypy_translation_info')


if sys.platform == 'win32' and sys.version_info > (2, 6):
    # 2.6's distutils.msvc9compiler can raise an IOError when failing to
    # find the compiler
    # It can also raise ValueError http://bugs.python.org/issue7511
    ext_errors = (CCompilerError, DistutilsExecError, DistutilsPlatformError,
                  IOError, ValueError)
else:
    ext_errors = (CCompilerError, DistutilsExecError, DistutilsPlatformError)


class BuildFailed(Exception):
    pass


class ve_build_ext(build_ext):
    # This class allows C extension building to fail.

    def run(self):
        try:
            build_ext.run(self)
        except DistutilsPlatformError:
            raise BuildFailed()

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except ext_errors:
            raise BuildFailed()


def run_setup(with_binary):
    cmdclass = {'test': Command}
    kw = {'cmdclass': cmdclass}

    # TODO: c extensions not working right now, disabling
    if 0: #with_binary:
        kw.update(
            ext_modules=[Extension("fastpolymath_c",
                                   sources=["polypasswordhasher/fastpolymath.c"],
                                   include_dirs=['polypasswordhasher'])],
            cmdclass=dict(cmdclass, build_ext=ve_build_ext),
        )

    setup(
        name="PolyPasswordHasher",
        version="0.1.0-alpha",
        packages=['polypasswordhasher', 'polypasswordhasher.tests'],
        url='https://github.com/PolyPasswordHasher/PolyPasswordHasher-Python',
        description="A Password hash storage scheme that prevents an attacker from cracking passwords individually and efficiently.",
        long_description=open('README.rst').read(),
        author="Justin Cappos",
        author_email="jcappos@poly.edu",
        install_requires=[
            "pycrypto"
        ],
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'Intended Audience :: Science/Research',
                     'Intended Audience :: System Administrators',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: OS Independent',
                     'Programming Language :: Python :: 2',
                     'Programming Language :: Python :: 3',
                     'Topic :: Security :: Cryptography',
                     'Topic :: Utilities'],
        **kw
    )

try:
    run_setup(not IS_PYPY)
except BuildFailed:
    BUILD_EXT_WARNING = ("WARNING: The C extension could not be compiled, "
                         "fast math is not enabled.")
    print('*' * 75)
    print(BUILD_EXT_WARNING)
    print("Failure information, if any, is above.")
    print("I'm retrying the build without the C extension now.")
    print('*' * 75)

    run_setup(False)

    print('*' * 75)
    print(BUILD_EXT_WARNING)
    print("Plain-Python installation succeeded.")
    print('*' * 75)
