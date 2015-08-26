#!/usr/bin/env python2

# Copyright 2015 Joel Allen Luellwitz and Andrew Klapp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import mailermonitor
import os
import signal
import sys
import timber
import traceback
import ConfigParser

PID_FILE = '/var/opt/run/gpgmailer.pid'

# Before first commit
# TODO: Fix handling of multiple recipients: use PGP API multi-key encryption
#	    instead of making multiple mails

# After first commit
# TODO: Make daemonize() a library
# TODO: Clean up logging
# TODO: Clean up method names
# TODO: Add a password to secret key and a config option for it

print('Loading configuration.')
config_file = ConfigParser.SafeConfigParser()
config_file.read('/etc/opt/gpgmailer/gpgmailer.conf')

# Figure out the logging options so that can start before anything else.
print('Verifying configuration.')
if(config_file.has_option('General', 'log_file') and (config_file.get('General', 'log_file') != '')):
    print(config_file.get('General', 'log_file'))
    LOG_FILE = config_file.get('General', 'log_file').strip()
else:
    LOG_FILE = '/var/opt/log/gpgmailer.log'

if(config_file.has_option('General', 'log_level') and (config_file.get('General', 'log_level') != '')):
    LOG_LEVEL= config_file.get('General', 'log_level').strip()
else:
    print('Log level undefined.  Exiting.')
    exit()

logger = timber.get_instance_with_filename(LOG_FILE, LOG_LEVEL)

def verify_string_parameter(param, config_file):
    logger.trace('Veryifing parameter %s' % param)
    if(config_file.has_option('General', param)):
        value = config_file.get('General', param).strip()
        if(value):
            logger.info('%s set to %s' % (param, value))
            return value
        else:
            logger.fatal('Parameter %s is empty.' % param)
            exit()
    else:
        logger.fatal('Parameter %s not set.' % param)
        exit()

def verify_quiet_parameter(param, config_file):
    logger.trace('Veryifing parameter %s' % param)
    if(config_file.has_option('General', param)):
        logger.trace('%s is defined.  Is it empty?' % param)
        value = config_file.get('General', param).strip()
        if(value):
            logger.info('%s set' % param)
            return value
        else:
            logger.fatal('Parameter %s is empty.' % param)
            exit()
    else:
        logger.fatal('Parameter %s not set.' % param)
        exit()

logger.info('Verifying non-logging config')
config = {}

config['gpg_dir'] = verify_string_parameter('gpg_dir', config_file)
config['watch_dir'] = verify_string_parameter('watch_dir', config_file)
config['smtp_user'] = verify_string_parameter('smtp_user', config_file)

config['smtp_pass'] = verify_quiet_parameter('smtp_pass', config_file)
config['smtp_server'] = verify_string_parameter('smtp_server', config_file)
config['smtp_port'] = verify_string_parameter('smtp_port', config_file)
config['smtp_max_idle'] = verify_string_parameter('smtp_max_idle', config_file)
config['smtp_sending_timeout'] = verify_string_parameter('smtp_sending_timeout', config_file)

# TODO: Verify that keys actually exist becuase the gpg module will fail silently
# 	if they do not.
# parse sender config.  <email>:<key fingerprint>
sender_raw = verify_string_parameter('sender', config_file)
sender_split = sender_raw.split(':')
if( len(sender_split[1]) != 40 ):
    logger.fatal('Sender key fingerprint is invalid')
    exit()
else:
    config['sender'] = { 'email' : sender_split[0], 'fingerprint' : sender_split[1] }

# parse recipient config.  Comma-delimited list of objects like sender
# <email>:<key fingerprint>,<email>:<key fingerprint>
config['recipients'] = []

recipients_raw = verify_string_parameter('recipients', config_file)
recipients_split = recipients_raw.split(',')
for r in recipients_split:
    r_split = r.split(':')
    if( len(r_split[1].strip()) != 40 ):
        logger.fatal('Recipient key fingerprint for %s is invalid.' % r_split[0] )
        exit()
    else:
        r_dict = { 'email' : r_split[0].strip(), 'fingerprint' : r_split[1].strip() }
        config['recipients'].append(r_dict)

logger.info('Verification complete')

def daemonize():
    # Fork the first time to make init our parent.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e: 
        logger.trace("Failed to make parent process init: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    os.chdir("/")  # Change the working directory
    os.setsid()  # Create a new process session.
    os.umask(0)

    # Fork the second time to make sure the process is not a session leader. 
    #   This apparently prevents us from taking control of a TTY.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        logger.trace("Failed to give up session leadership: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())
    os.close(devnull)

    pid = str(os.getpid())
    pidFile = file(PID_FILE,'w')
    pidFile.write("%s\n" % pid)
    pidFile.close()

daemonize()

# Quit when SIGTERM is received
def sig_term_handler(signal, stack_frame):
    logger.trace("Quitting.")
    sys.exit(0)

signal.signal(signal.SIGTERM, sig_term_handler)

try:
    the_watcher = mailermonitor.mailer_monitor(config)
    the_watcher.start_monitoring()  

except Exception as e:
    logger.trace("Fatal %s: %s\n" % (type(e).__name__, e.message))
    logger.trace(traceback.format_exc())
    sys.exit(1)
