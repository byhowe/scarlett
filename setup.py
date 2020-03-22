#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="scarlett",
    version="0.2",
    packages=find_packages(),

    install_requires=[
        "finian",
        "zila",
        "rsa",
        "pymongo",
        "passlib"
    ],

    author=""Byron"",
    author_email="37745048+byhowe@users.noreply.github.com",
    description="A chatting server written using finian.",
    url="https://github.com/byhowe/scarlett",

    entry_points={
        "console_scripts": [
            "scarlett = scarlett.scripts.run:main"
        ]
    }
)
