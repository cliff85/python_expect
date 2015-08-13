#!/usr/bin/env python

import re
import pxssh
import getpass
import logging
import pexpect
import sys


global PROMPT
global SUDOPROMPT
UNIQUE_PROMPT = "\[PEXPECT\]\$ "
UNIQUE_SUDOPROMPT = "\[PEXPECT\]\# "
PROMPT = UNIQUE_PROMPT
SUDOPROMPT = UNIQUE_SUDOPROMPT

#Logging information
logger = logging.getLogger('test_login')
hdlr = logging.FileHandler('test_login.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

#User Info
username = 'cfrasure'
password = getpass.getpass('Password: ')
create_user = sys.argv[1]
create_password = sys.argv[2]
create_gid = sys.argv[3]


def get_servers():
	with open('serverlist') as f:
		lines = f.read().splitlines()
		return lines

def execute(hostname):	
	try:
		logger.info("Connecting to %s" % hostname)
		s = pxssh.pxssh(maxread=1)
#		s.login(hostname, username, password)
#		Enable above if you dont have a key
		s.login(hostname, username)
		s.sendline ("PS1='[PEXPECT]\$ '") # In case of sh-style
		s.expect (PROMPT, timeout=15)
		print "Sudo to root"
		s.sendline('sudo su -')
		i = s.expect(['password.*:'])
		if i==0:
			print "Sending sudo password"
			s.sendline(password)
		else:
			pass
		s.prompt()
		s.sendline ("PS1='[PEXPECT]\$ '") # In case of sh-style
		s.expect (SUDOPROMPT, timeout=15)
		print "adding group"
		s.sendline('groupadd -g %s %s' % (create_gid, create_user))
		s.expect (SUDOPROMPT, timeout=5)
		print "adding user"
		s.sendline('useradd -u %s -g %s -m -d /home/%s %s' % (create_gid, create_user, create_user, create_user))
		s.expect (SUDOPROMPT, timeout=5)
		print s.before
		s.sendline('echo "%s:%s" | chpasswd -c SHA512' % (create_user, create_password) )
		s.expect (SUDOPROMPT, timeout=5)
		s.sendline('exit')
		s.expect (PROMPT, timeout=5)
		s.logout()
	except pxssh.ExceptionPxssh, e:
		print "pxssh failed on login."
		#print str(e)

def run_execute():
	serverlist = get_servers()
	for i in serverlist:
		print "connecting to %s....." % i
		execute(i)

run_execute()
