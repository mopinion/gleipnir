"""Packaging settings."""


from codecs import open
from os.path import abspath, dirname, join
from subprocess import call

from setuptools import Command, find_packages, setup

from gleipnir import __version__


this_dir = abspath(dirname(__file__))
with open(join(this_dir, 'README.rst'), encoding='utf-8') as file:
	long_description = file.read()

setup(
	name = 'gleipnir',
	version = __version__,
	description = 'Connecting to your AWS instances',
	long_description = long_description,
	url = 'https://github.com/mopinion/gleipnir',
	author = 'Floris Snuif',
	author_email = 'floris@mopinion.com',
	license = 'MIT',
	classifiers = [
		'Intended Audience :: Developers',
		'Topic :: Utilities',
		'License :: Public Domain',
		'Natural Language :: English',
		'Operating System :: OS Independent',
		'Programming Language :: Python :: 2',
		'Programming Language :: Python :: 2.6',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.2',
		'Programming Language :: Python :: 3.3',
		'Programming Language :: Python :: 3.4',
		'Programming Language :: Python :: 3.6',
		'Programming Language :: Python :: 3.7',
	],
	keywords = 'cli',
	packages = find_packages(exclude=['docs']),
	install_requires = [
		'docopt',
		'boto3',
	],
	extras_require = {
		'test': ['coverage', 'pytest', 'pytest-cov'],
	},
	entry_points = {
		'console_scripts': [
			'gleipnir=gleipnir.cli:main',
		],
	},
)
