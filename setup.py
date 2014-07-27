#!/usr/bin/python

from setuptools import setup, find_packages

name = 'zerocloud'
version = '0.1'

setup(
    name=name,
    version=version,
    description='zerocloud',
    license='',
    author='',
    author_email='',
    url='',
    packages=find_packages(exclude=['test', 'bin']),
    test_suite='nose.collector',
    classifiers=[],
    install_requires=[],
    scripts=[],
    entry_points={
        'paste.filter_factory': [
            'proxy_query=zerocloud.proxyquery:filter_factory',
            'object_query=zerocloud.objectquery:filter_factory',
            'zero_queue=zerocloud.queue:filter_factory',
            'job_chain=zerocloud.chain:filter_factory'
        ],
    },
)
