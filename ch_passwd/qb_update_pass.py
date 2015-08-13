#!/usr/bin/env python

import re
import pxssh
import pexpect
import sys

global PROMPT
global SUDOPROMPT
UNIQUE_PROMPT = "\[PEXPECT\]\$ "
UNIQUE_SUDOPROMPT = "\[PEXPECT\]\# "
PROMPT = UNIQUE_PROMPT
SUDOPROMPT = UNIQUE_SUDOPROMPT

#User Info
username = sys.argv[1]
#password = getpass.getpass('Password: ')
password = sys.argv[2]
user_login = sys.argv[3]
user_password = sys.argv[4]
server = sys.argv[5]


def get_servers():
	with open('serverlist') as f:
		lines = f.read().splitlines()
		return lines

def change_password(child, password, user_login, user_password):

	child.sendline('sudo passwd %s' % user_login)
	i = child.expect(['password.*:'])
	if i==0:
		print "Sending sudo password"
		child.sendline(password)
	else:
		pass
	child.expect('(?i)new.*password:')
	child.sendline(user_password)
	child.expect('(?i)new.*password:')
 	child.sendline(user_password)
	i = child.expect(['(?i)new.*password:', 'do not match', 'successfully'])
	if i == 0:
		print('Host did not like new password. Here is what it said...')
		print(child.before+child.match.string)
		# On Linux, sending Ctrl-C can't quit passwd. 
		while(1):
			child.sendline()
			# passwd: Authentication token manipulation error
			r = child.expect(['(?i)new.*password:', 'error'])
			if(r == 1):
				break
		return -1
	if(i==1):
		print('Sorry, passwords do not match.')
 		return -2
	print('Password updated successfully.')
	return 0


def execute(hostname):
	try:
		s = pxssh.pxssh(maxread=1)
		s.login(hostname, username, password)
#		Enable above if you dont have a key
#		s.login(hostname, username)
		s.sendline ("PS1='[PEXPECT]\$ '") # In case of sh-style
		s.expect (PROMPT, timeout=5)
		print "Sudo to root"
		change_password(s, password, user_login, user_password)
		s.expect (PROMPT, timeout=5)
		s.logout()
	except pxssh.ExceptionPxssh, e:
		print "pxssh failed on login."
		#print str(e)

def run_execute():
	print "connecting to %s....." % server
	execute(server)

run_execute()
