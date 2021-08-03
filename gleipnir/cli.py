"""
gleipnir

Usage:
  gleipnir connect [--server <server> | -s <server>] [--user <user> | -u <user>] [--password <pass> | -p <pass>] [--mosh | -m] [--verbose | -v]
  gleipnir connect [--host <host> | -h <host>] [--user <user> | -u <user>] [--password <pass> | -p <pass>] [--mosh | -m] [--verbose | -v]

Options:
  -s --server           Search for server name
  -u --user							User (optional)
  -p --password					Use password (optional)
  -h --host							Host (optional)
  -m --mosh             Mosh (optional)
  -v --verbose          Verbose (optional)

Examples:
  gleipnir connect -s test -u ubuntu -p 1

Help:

  Gleipnir is a nice little tool by Mopinion (mopinion.com) to easily connect to AWS servers through CLI

  Environment variables to set:
  - AWS_ACCESS_KEY_ID: your AWS access key id
  - AWS_SECRET_ACCESS_KEY: your AWS secret access key
  - AWS_REGION: your AWS region
  - AWS_PASSWORD: custom password for SSH (optional)
  - AWS_KEY_FILE: location of your key file

  For help using this tool:
  https://github.com/mopinion/Gleipnir
"""


from inspect import getmembers, isclass

from docopt import docopt

from . import __version__ as VERSION


def main():
	"""Main CLI entrypoint."""
	import gleipnir.commands
	options = docopt(__doc__, version=VERSION)
	# Here we'll try to dynamically match the command the user is trying to run
	# with a pre-defined command class we've already created.
	for (k, v) in options.items():
		if hasattr(gleipnir.commands, k) and v:
			module = getattr(gleipnir.commands, k)
			gleipnir.commands = getmembers(module, isclass)
			command = [command[1] for command in gleipnir.commands if command[0] != 'Base'][0]
			command = command(options)
			command.run()
