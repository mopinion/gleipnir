"""Connect to an instance."""
from json import dumps
from .base import Base
import subprocess
import boto3
import os
import re
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


class Connect(Base):
	"""Connect to an instance"""

	def run(self):
		self.action()

	def action(self):
		if '--server' in self.options and self.options['--server']:
			# find server
			server_name = self.options['<server>'] if '<server>' in self.options else ''
			servers = self.find(term=server_name, dynamic_keys=False)
			if len(servers) > 1:
				# show possible servers
				print('==============================')
				print('Multiple instances were found:')
				print('==============================')
				for server in servers:
					print('> {} ({} / {}) @ {}'.format(server['tag'], server['ip'], server['dns'], server['datetime']))
				print('-------------------------------')
			elif len(servers) == 1:
				# connect to server
				print('==============================')
				print('Server found: {}'.format(servers[0]['tag']))
				print('==============================')
				self.connect(servers[0]['ip'])
			else:
				# no servers found
				print('==============================')
				print('No instances found...')
				print('==============================')
		elif '--host' in self.options and self.options['--host'] is not None:
			self.connect(self.options['--host'])
		else:
			print('what would you like to connect to? use -s or --server')

	def connect(self, server=None):
		# user
		user = self.options['--user'] if '--user' in self.options and self.options['--user'] else 'ubuntu'
		# passwd
		password = os.getenv('AWS_PASSWORD') if '--password' in self.options and self.options['--password'] else None
		# mosh
		mosh = True if '--mosh' in self.options and self.options['--mosh'] else True if os.getenv('MOSH') else False
		self.ssh(user=user, server=server, password=password, mosh=mosh)

	def find(self, term='', server=None, dynamic_keys=False):
		# find instance properties from (part of) name
		instances = self.instances()
		servers = []
		for reservation in instances['Reservations']:
			if 'Tags' in reservation['Instances'][0] and len(reservation['Instances'][0]['Tags']) > 0:
				# state
				instance = reservation['Instances'][0]
				state = instance['State']['Name'] if 'State' in instance and 'Name' in instance['State'] else None
				# tags
				tags = reservation['Instances'][0]['Tags']
				tags = [tag for tag in tags if 'Key' in tag and tag['Key'] == 'Name']
				tag = tags[0] if len(tags) > 0 else {}
				if (((reservation['Instances'][0].get('PublicIpAddress') == server or reservation['Instances'][0].get('PublicDnsName') == server) and dynamic_keys) or ('Key' in tag and tag['Key'] == 'Name' and re.search(term, tag['Value']) is not None) and not dynamic_keys) and state == 'running':  # term in tag['Value']:
					servers.append({
						'tag': tag['Value'],
						'ip': reservation['Instances'][0]['PublicIpAddress'] if 'PublicIpAddress' in reservation['Instances'][0] else '-',
						'dns': reservation['Instances'][0]['PublicDnsName'],
						'datetime': reservation['Instances'][0]['LaunchTime'],
						'instance_id': reservation['Instances'][0]['InstanceId'],
						'availability_zone': reservation['Instances'][0]['Placement'].get('AvailabilityZone'),
					})
		# info
		if self.options.get('--verbose', False):
			print('servers found: {}'.format(len(servers)))
		return servers

	def ssh(self, key_file=None, user='ubuntu', server='localhost', password=None, mosh=True):
		# AWS private key file
		aws_key_file = os.environ.get('AWS_KEY_FILE')
		# key argument
		if not aws_key_file:
			# no private key file set -> use EC2 instance connect
			# server info
			# info
			if self.options.get('--verbose', False):
				print('searching server {}...'.format(server))
			servers = self.find(server=server, dynamic_keys=True)
			host = servers[0] if len(servers) > 0 else None
			if host:
				# generate key pair
				self.generateKeyPair()
				# send pubic key to server
				self.sendPublicKey(instance_id=host['instance_id'], user=user, avail_zone=host['availability_zone'], server=server)
				# key
				key = '-i {} '.format(self.keyName(public=False))
			else:
				# not found
				print('server not found...')
		else:
			# use set private key file
			key = '-i {} '.format(aws_key_file) if not password and aws_key_file else ''
		# key
		command = 'ssh {}{}@{}'.format(key, user, server)
		# passwd
		command = 'sshpass -p {} {}'.format(password, command) if password else command
		# mosh
		command = 'mosh {}@{} --ssh "ssh {}"'.format(user, server, key) if mosh else command
		print('$ {}'.format(command))
		os.system(command)

	def client(self, service=None):
		access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
		secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
		region = os.environ.get('AWS_REGION')
		return boto3.client(service, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

	def instances(self):
		# get all EC2 instances
		client = self.client(service='ec2')
		instances = client.describe_instances()
		return instances

	def sendPublicKey(self, instance_id=None, user=None, avail_zone=None, server=None):
		'''
		send public key to instance for use in Instance Connect
		'''
		# boto client
		client = self.client(service='ec2-instance-connect')
		# get public key
		public_key_file = self.keyName(public=True)
		public_key = open(public_key_file, 'rb').read()
		# send key
		try:
			response = client.send_ssh_public_key(InstanceId=instance_id, InstanceOSUser=user, SSHPublicKey=public_key.decode(), AvailabilityZone=avail_zone)
		except Exception as e:
			if self.options.get('--verbose', False):
				print('error uploading public key:')
				print(e)
			return
		# info
		if self.options.get('--verbose', False):
			print('public key {} sent to instance {} ({})'.format(public_key_file, instance_id, server))
			print(response)
		return response

	def generateKeyPair(self, use_public_pem=False):
		'''
		generate RSA key pair for connecting via SSH
		'''
		# generate key
		key = rsa.generate_private_key(
			backend=crypto_default_backend(),
			public_exponent=65537,
			key_size=2048
		)
		# private key
		private_key = key.private_bytes(
			crypto_serialization.Encoding.PEM,
			crypto_serialization.PrivateFormat.PKCS8,
			crypto_serialization.NoEncryption()
		)
		# save to private key file
		private_key_file = self.keyName(public=False)
		open(private_key_file, 'wb').write(private_key)
		# set rights
		os.system('chmod 600 {}'.format(private_key_file))
		# info
		if self.options.get('--verbose', False):
			print('private key saved @ {}'.format(private_key_file))
		# encoding / format
		encoding = crypto_serialization.Encoding.PEM if use_public_pem else crypto_serialization.Encoding.OpenSSH
		format = crypto_serialization.PublicFormat.SubjectPublicKeyInfo if use_public_pem else crypto_serialization.PublicFormat.OpenSSH
		# public key
		public_key = key.public_key().public_bytes(
			encoding=encoding,
			format=format
		)
		# save to public key file
		public_key_file = self.keyName(public=True)
		open(public_key_file, 'wb').write(public_key)
		# set rights
		os.system('chmod 600 {}'.format(public_key_file))
		# info
		if self.options.get('--verbose', False):
			print('public key saved @ {}'.format(public_key_file))

	def keyName(self, public=False):
		'''
		return key location/name
		'''
		# SSH location
		ssh_loc = '{}/.ssh'.format(os.getenv('HOME'))
		if public:
			# public key
			return '{}/gleipnir.public.pem'.format(ssh_loc)
		else:
			# private key
			return '{}/gleipnir.private.pem'.format(ssh_loc)

	def sshpass(self):
		command = 'brew install https://raw.githubusercontent.com/kadwanev/bigboybrew/master/Library/Formula/sshpass.rb'
		self.cmd(command)

	def cmd(self, command=''):
		proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		(out, err) = proc.communicate()
		return out
