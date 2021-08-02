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
			servers = self.find(term=server_name)
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
		elif '--host' in self.options and self.options['--host'] != None:
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

	def find(self, term=''):
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
				if 'Key' in tag and tag['Key'] == 'Name' and re.search(term, tag['Value']) != None and state == 'running':  # term in tag['Value']:
					servers.append({
						'tag': tag['Value'],
						'ip': reservation['Instances'][0]['PublicIpAddress'] if 'PublicIpAddress' in reservation['Instances'][0] else '-',
						'dns': reservation['Instances'][0]['PublicDnsName'],
						'datetime': reservation['Instances'][0]['LaunchTime']
					})
		return servers

	def ssh(self, key_file=None, user='ubuntu', server='localhost', password=None, mosh=True):
		key = '-i {} '.format(os.environ.get('AWS_KEY_FILE')) if not password and os.environ.get('AWS_KEY_FILE') else ''
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

	def sendPublicKey(self, instance_id=None, user=None, avail_zone=None):
		'''
		send public key to instance for use in Instance Connect
		'''
		# boto client
		client = self.client(service='ec2-instance-connect')
		# get public key
		public_key = open(self.keyName(public=True), 'rb').read()
		# send key
		response = client.send_ssh_public_key(InstanceId=instance_id, InstanceOSUser=user, SSHPublicKey=public_key.decode(), AvailabilityZone=avail_zone)
		return response

	def generateKeyPair(self):
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
		open(self.keyName(public=False), 'wb').write(private_key)
		# public key
		public_key = key.public_key().public_bytes(
			encoding=crypto_serialization.Encoding.OpenSSH,
			format=crypto_serialization.PublicFormat.OpenSSH
		)
		open(self.keyName(public=True), 'wb').write(public_key)

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
