#!/usr/bin/python

###
## ss.py - StatSend
## By DimeCadmium. Copyright 2011 John Runyon.
###
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

ver = 1.2

import socket, os, sys, re, getopt, json

try:
	import ssconf
except ImportError, err:
	print "Couldn't import the config."
	raise err

def args():
	global confpath
	try:
		opts, args = getopt.gnu_getopt(sys.argv[1:], "v")
	except getopt.GetoptError, err:
		print str(err)
		print "Flags:"
		print " -v (version)"
	for o, a in opts:
		if o == "-v":
			print "SS - StatSend"
			print "<http://github.com/DimeCadmium/ss>"
			print "Copyright 2011 John Runyon."
			print "Version %.1f" % ver
			sys.exit(0)

def put(sock, buf):
	if isinstance(buf, (list, tuple)):
		for scalar in buf: put(sock, scalar)
	else:
		sock.send(str(buf)+"\r\n")

def getHostname():
	rp = os.popen("/bin/hostname")
	line = rp.readline()
	return line.strip()
def getPS():
	apps = []
	run = 0
	svcs = {}
	lines = []
	rp = os.popen("/bin/ps ax -o command=")
	flines = rp.readlines()
	for l in flines:
		lines.append((l.strip().split(' '))[0])
	for pn in ssconf.procs:
		if pn in lines:
			svcs[pn] = True
			run += 1
		else:
			svcs[pn] = False
	dic = {}
	dic['allps'] = len(lines)
	dic['runsvc'] = run
	dic['allsvc'] = len(ssconf.procs)
	dic['svcs'] = svcs
	return dic
def getWho():
	users = {}
	rp = os.popen("/usr/bin/who -q")
	line = rp.readline()
	words = line.strip().split(' ')
	for v in words:
		try: users[v] += 1
		except KeyError: users[v] = 1
	return users
def getIPs():
	ary = []
	rp = os.popen("/sbin/ifconfig | grep 'inet addr:' | grep -v '127.0.0.1' | cut -d: -f2 | awk '{print $1}'")
	lines = rp.readlines()
	for line in lines:
		ip = line.strip()
		host = socket.getfqdn(ip)
		ary.append({'ip': ip, 'host': host})
	return ary
def getUptime():
	rp = os.popen("/usr/bin/uptime")
	line = rp.readline()
	sects = line.split(', ', 2)
	timeuptime = sects[0]
	textload = sects[2]
	uptime = (timeuptime.split('up '))[1].strip()
	loads = (textload.split(': '))[1].split(', ')
	load1 = float(loads[0].strip())
	load5 = float(loads[1].strip())
	load15 = float(loads[2].strip())
	return {'uptime': uptime, 'load1': load1, 'load5': load5, 'load15': load15}
def getRAM():
	rp = os.popen("/usr/bin/free -m")
	rp.readline()
	line = rp.readline()
	words1 = line.split(' ')
	words = []
	for w in words1:
		if w != '': words.append(w)
	total = int(words[1])
	used = int(words[2])
	free = int(words[3])
	bufcac = int(words[5])+int(words[6])
	return {'used': used, 'free': free, 'total': total, 'bufcac': bufcac}
def getDisk():
	dics = {'single': [], 'total': {'avail': 0, 'used': 0, 'total': 0}}
	last = []
	rp = os.popen("/bin/df -TP -B 1073741824")
	rp.readline()
	lines = rp.readlines()
	for l in lines:
		m = re.match(r"(.+?)\s+([\w\-]+)\s+([\d.]+\w?)\s+([0-9.]+\w?)\s+([0-9.]+\w?)\s+(?:\d+%)\s*(.*)", l).groups()
		# TYPE:FS:MP:TOTAL:USED:AVAIL
		dics['single'].append({'type': m[1], 'fs': m[0], 'mount': m[5], 'total': int(m[2]), 'used': int(m[3]), 'avail': int(m[4])})
	for item in dics['single']:
		dics['total']['total'] += item['total']
		dics['total']['used'] += item['used']
		dics['total']['avail'] += item['avail']
	return dics
def getInterfaces():
	dev = open("/proc/net/dev", "r").readlines()

	values={}
	for line in dev[2:]:
		intf = line[:line.index(":")].strip()
		if intf in ssconf.interfaces:
			values[intf] = [int(value) for value in line[line.index(":")+1:].split()]
	return values

args()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(ssconf.remote)

dic = {
	"hostname": getHostname(),
	"interfaces": getInterfaces(),
	"ps": getPS(),
	"who": getWho(),
	"uplo": getUptime(),
	"ram": getRAM(),
	"ips": getIPs(),
	"disk": getDisk(),
	"key": ssconf.key,
	"uid": ssconf.uid,
}
dump = json.dumps(dic)

put(s, "POST %s HTTP/1.1" % ssconf.page)
put(s, "Host: %s" % ssconf.remote[0])
put(s, "Content-Type: application/x-www-form-urlencoded")
put(s, "Content-Length: %d" % len(dump))
put(s, "User-Agent: SS/%.1f" % ver)
put(s, "Connection: close")
put(s, "")
put(s, dump)
put(s, "")

print socket.read(30)

try:
	s.shutdown(socket.SHUT_RDWR)
	s.close()
except socket.error, err:
	pass
