# -*- coding: utf-8 -*-

"""setup.py"""

import os
import sys

# import pkg_resources
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class Tox(TestCommand):
    user_options = [("tox-args=", "a", "Arguments to pass to tox")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import tox
        import shlex

        if self.tox_args:
            errno = tox.cmdline(args=shlex.split(self.tox_args))
        else:
            errno = tox.cmdline(self.test_args)
        sys.exit(errno)


def read_content(filepath):
    with open(filepath) as fobj:
        return fobj.read()


classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
]


def get_requirements():
    if sys.version_info[0] == 2:
        filename = "requirements-py26.txt"
    else:
        filename = "requirements.txt"

    with open(filename) as f:
        return f.read().splitlines()


DEPENDENCY_LINKS = []


long_description = read_content("README.rst") + read_content(
    os.path.join("docs/source", "CHANGELOG.rst")
)

extras_require = {"reST": ["Sphinx"]}
if os.environ.get("READTHEDOCS", None):
    extras_require["reST"].append("recommonmark")

setup(
    name="pubtools-pyxis",
    version="1.3.2",
    description="Pubtools-pyxis",
    long_description=long_description,
    long_description_content_type='text/x-rst',
    author="Lubomir Gallovic",
    author_email="lgallovi@redhat.com",
    url="https://github.com/release-engineering/pubtools-pyxis",
    classifiers=classifiers,
    packages=find_packages(exclude=["tests"]),
    data_files=[],
    install_requires=get_requirements(),
    dependency_links=DEPENDENCY_LINKS,
    entry_points={
        "console_scripts": [
            "pubtools-pyxis-get-operator-indices = pubtools._pyxis.pyxis_ops:get_operator_indices_main",
            "pubtools-pyxis-get-repo-metadata = pubtools._pyxis.pyxis_ops:get_repo_metadata_main",
            "pubtools-pyxis-upload-signatures = pubtools._pyxis.pyxis_ops:upload_signatures_main",
            "pubtools-pyxis-get-signatures = pubtools._pyxis.pyxis_ops:get_signatures_main",
            "pubtools-pyxis-delete-signatures = pubtools._pyxis.pyxis_ops:delete_signatures_main"
        ]
    },
    include_package_data=True,
    extras_require=extras_require,
    tests_require=["tox"],
    cmdclass={"test": Tox},
)
