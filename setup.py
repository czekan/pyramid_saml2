# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages

requires = [
    'pyramid',
    'attrs>=18.1.0',
    'signxml>=2.4.0',
    'lxml>=3.8.0',
    'pyopenssl>=22.10',
    'pytz>=0',
    'pyramid_jinja2',
]

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    long_description = f.read()

with open(os.path.join(here, 'CHANGELOG.md')) as f:
    long_description += '\n\n'
    long_description += f.read()

setup(
    name='pyramid_saml2',
    version='0.1',
    description='Pyramid SAML IdP',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Tomasz Czekanski',
    author_email='',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Framework :: Pyramid',
        'Topic :: Internet :: WWW/HTTP'
    ],
    url='https://github.com/czekan/pyramid_saml2',
    keywords='web pyramid saml2 idp',
    install_requires=requires,
    packages=find_packages(exclude=['demo', 'test*']),
    include_package_data=True
)
