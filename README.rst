Gleipnir
========

*Hold Fenrir 🐺*

Tool to easily connect to your AWS servers

Install
-------
	$ pip install gleipnir

Usage
-----
	$ gleipnir connect -s "my server name tag"

Searches for EC2 instances by Name tag (regex enabled)

When more than one instance is found it returns a list.
If just one instance is found it connects.

	$ gleipnir connect -h 192.168.1.1

Connects to server by IP/URL

Environment variables
---------------------

You should set the following environment variables:

- AWS_ACCESS_KEY_ID: your AWS access key id
- AWS_SECRET_ACCESS_KEY: your AWS secret access key
- AWS_REGION: your AWS region
- AWS_PASSWORD: custom password for SSH (optional)
- AWS_KEY_FILE: location of your key file

Thanks
------
**Mopinion.com**
