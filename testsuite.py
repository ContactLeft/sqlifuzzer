#!/usr/bin/env python

import subprocess
import os, re

def purge(dir, pattern):
    for f in os.listdir(dir):
    	if re.search(pattern, f):
    		os.remove(os.path.join(dir, f))

print "Cleanup."

purge('./session/','_-logs-testsuite-*')
purge('./output/','_-logs-testsuite-*')

print"Testing."
print "001 - MSSQL - Integer - GET"
subprocess.check_call(['./sqlifuzzer-0.7.2.sh', '-l ./logs/testsuite/001.log', '-n', '-t http://192.168.52.128'])

print "002 - MSSQL - Integer - POST"
subprocess.check_call(['./sqlifuzzer-0.7.2.sh', '-l ./logs/testsuite/002.log', '-n', '-t http://192.168.52.128'])

print "003 - MSSQL - String - GET"
subprocess.check_call(['./sqlifuzzer-0.7.2.sh', '-l ./logs/testsuite/003.log', '-s', '-t http://192.168.52.128'])

print "004 - MSSQL - String - POST"
subprocess.check_call(['./sqlifuzzer-0.7.2.sh', '-l ./logs/testsuite/004.log', '-s', '-t http://192.168.52.128'])

