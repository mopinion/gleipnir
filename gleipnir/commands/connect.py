"""Connect to an instance."""
from json import dumps
from .base import Base
import subprocess
import boto3
import os
import re

class Connect(Base):
	"""Connect to an instance"""

	def run(self):
		# print('connect!')
		# print('You supplied the following options:', dumps(self.options, indent=2, sort_keys=True))
		self.action()

	def action(self):
		if '--server' in self.options and self.options['--server']:
			# find server
			server_name = self.options['<server>'] if '<server>' in self.options else ''
			servers = self.find(term=server_name)
			if len(servers) > 1:
				print('==============================')
				print('Multiple instances were found:')
				print('==============================')
				for server in servers:
					print('> {} ({} / {})'.format(server['tag'], server['ip'], server['dns']))
				print('-------------------------------')
			elif len(servers) == 1:
				# connect to server
				print('==============================')
				print('Server found: {}'.format(servers[0]['tag']))
				print('==============================')
				user = self.options['--user'] if '--user' in self.options and self.options['--user'] != None else 'ubuntu'
				password = os.environ.get('AWS_PASSWORD') if '--password' in self.options and self.options['--password'] != None else None
				self.ssh(user=user,server=servers[0]['ip'],password=password)
			else:
				print('==============================')
				print('No instances found...')
				print('==============================')
		else:
			print('what would you like to connect to? use -s or --server')

	def find(self,term=''):
		# find instance properties from (part of) name
		instances = self.instances()
		servers = []
		# print(instances['Reservations'][0]['Instances'][0]['PublicIpAddress'])
		for reservation in instances['Reservations']:
			if 'Tags' in reservation['Instances'][0] and len(reservation['Instances'][0]['Tags']) > 0:
				tag = reservation['Instances'][0]['Tags'][0]
				if tag['Key'] == 'Name' and re.search(term, tag['Value']) != None: # term in tag['Value']:
					servers.append({
						'tag': reservation['Instances'][0]['Tags'][0]['Value'],
						'ip': reservation['Instances'][0]['PublicIpAddress'],
						'dns': reservation['Instances'][0]['PublicDnsName'],
					})
		return servers

	def ssh(self,key_file=None,user='ubuntu',server='localhost',password=None):
		key = '-i {} '.format(os.environ.get('AWS_KEY_FILE')) if password == None and os.environ.get('AWS_KEY_FILE') != None else ''
		command = 'ssh {}{}@{}'.format(key, user, server)
		command = 'sshpass -p {} {}'.format(password, command) if password != None else command
		print '$ {}'.format(command)
		# self.cmd(command)
		os.system(command)
		# s = pxssh.pxssh()
		# s.login(server, user, password)
		# s.prompt()

	def client(self, service=None):
		access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
		secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
		region = os.environ.get('AWS_REGION')
		return boto3.client(service, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key,region_name=region)

	def instances(self):
		# get all EC2 instances
		client = self.client(service='ec2')
		instances = client.describe_instances()
		return instances

	def sshpass(self):
		command = 'brew install https://raw.githubusercontent.com/kadwanev/bigboybrew/master/Library/Formula/sshpass.rb'
		self.cmd(command)

	def cmd(self,command=''):
		proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		(out, err) = proc.communicate()
		return out
