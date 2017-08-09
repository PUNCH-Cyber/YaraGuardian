#! /usr/bin/env python3

from setuptools import setup

setup(
    name             =   "Plyara",
    packages         =   ['plyara'],
    version          =   '0.2.0',
    description      =   'Parse Yara Rules',
    install_requires =   ['ply>=3.7'],
    test_suite       =   'plyara.tests.unit_tests'
)
