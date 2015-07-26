#!/usr/bin/env python
from distutils.core import setup
setup(
    name="ashens",
    version="0.1.0",
    author="Fylwind",
    author_email="fyl@wolfpa.ws",
    url="https://github.com/Fylwind/ashens",
    py_modules=["ashens"],
    license="MIT",
    install_requires=[
        "beautifulsoup4",
        "dateutil",
        "requests",
    ],
)
