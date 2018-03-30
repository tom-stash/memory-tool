#!/usr/bin/python
import argparse
import os
import subprocess
import re
import sys
import glob
import hashlib

# Requirements
# - pip install dpapick
# - pip install distorm3

class vol_process(object):

	# Constructor using path of memory image
	def __init__(self, path_raw):
		self.path_raw = path_raw
	
	# Function to return sha256 of given file	
	def sha256(self, fname):
		hash_sha256 = hashlib.sha256()
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(2 ** 20), b""):
				hash_sha256.update(chunk)
		return hash_sha256.hexdigest()

	# Function to output results of each plugin to file
	def output_results(self, tool, plugin, output):
		filename = args.image+'_'+tool+'_'+plugin+'.txt'
		f = open(filename, 'wb')
		f.write(output)
		f.close()
		print '[-] ' +plugin+ ' --results output to ' +filename

	# Function to run Volatility
	def run_v(self):
		print '[i] Using image: ' + self.path_raw
		if not os.path.isfile(args.image):
			print '[!] Image not found!'
			sys.exit()
	
		print '[i] Starting Volatility process...'
		
		# Get profile and kdbg
		self.profile, self.kdbg = self.get_profile()
		
		# Run selected plugins
		vol_cmds = {'pstree':'', \
					'connscan':'' \
		}
		self.run_plugins(vol_cmds)
		
		# Process output
		self.process_output()
	
	# Function to get profile and kdbg values	
	def get_profile(self):
		print '[i] Determining profile and kdbg values...'
		proc = subprocess.Popen(['python2.7', 'vol.py', '-f', self.path_raw, \
			'imageinfo'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out = proc.stdout.read()

		# Extract profile and kdbg values from imageinfo output
		profile = re.search("Suggested Profile\(s\) : (.*)", out)
		kdbg = re.search("KDBG : (0x.*?)L", out)

		# Exit if this profile or kdbg is not found
		if not profile or not kdbg:
			print '[!] Something went wrong - '+\
				'have you converted aff4 to raw with WinPMem?'
			print '[i] Complete.'
			sys.exit(0)

		profiles = profile.group(1).split(', ')
		# Use the first profile - could cycle through if neccesary
		profile = profiles[0]
		print '[-] --profile: ' + profile
		kdbg = kdbg.group(1)
		print '[-] --kdbg: ' + kdbg
		self.output_results('volatility', 'imageinfo', out)
		
		return profile, kdbg
		
	def run_plugins(self, vol_cmds):
		print '[i] Running selected plugins...'
		for plugin in vol_cmds:
			cmd = 'python2.7 vol.py ' + \
				vol_cmds[plugin] + \
				'-f ' + self.path_raw + \
				' --profile=' + self.profile + \
				' --kdbg=' + self.kdbg + \
				' ' + plugin
			cmd = cmd.split(' ')
			proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,\
					stderr=subprocess.PIPE)
			out = proc.stdout.read()
			self.output_results('volatility', plugin.split(' ')[0], out)
	
	# Function to process plugin output files
	def process_output(self):
	
		# Create directory for binaries
		if not os.path.exists('binaries'):
			os.makedirs('binaries')
			    		
		self.process_pstree()
		self.process_connscan()
    		
    # Function to process the output file for pstree		
	def process_pstree(self):
		# Confirm the output files of the pstree plugin exist
		if os.path.isfile(self.path_raw+"_volatility_pstree.txt"):
	
			print '[i] Checking processes...'

			self.procs = []
			f = open(args.image+"_volatility_pstree.txt")
			for l in f:
				volatility = re.search(\
				"(.*0x.*?):(.*?)[ ]+([0-9]*?)[ ]+([0-9]*?) .*?([1-2][0-9][0-9][0-9]-.*?) UTC", l)
				if volatility:
					try:
						vol = []
						vol.append(volatility.group(1)) # 0 hex
						vol.append(volatility.group(2)) # 1 name
						vol.append(volatility.group(3)) # 2 src ip:port
						vol.append(volatility.group(4)) # 3 dst ip:port
						vol.append(volatility.group(5)) # 4 pid
						if volatility.group(2) != '':
							self.procs.append(vol)
					except:
						pass
		
			# Create process, id lookup
			self.procids = {}
			for process in self.procs:
				self.procids[process[2]] = process[1]

			# Look for and alert on any anomalies
			for process in self.procs:

				# Misspelt process names
				# Add misspelt process to this list
				misspelt = ['scvhost', 'svhost', 'lssass', 'wsock32', 'kerne132', \
					'isass', 'nvcpl.exe', 'crss']
				for name in misspelt:
					if name in process[1].lower():
						print '[!] Misspelt process name - '+process[1]+' ('+\
							process[2]+')'

				# Check for parents
				# Add parents to this dict
				parents = {	'svchost.exe':'services.exe', \
							'smss.exe':'System', \
							'wininit.exe':['','smss.exe'], \
							'taskhost.exe':'services.exe', \
							'lsass.exe':['wininit.exe','winlogon.exe'], \
							'winlogon.exe':['','smss.exe'], \
							'iexplore.exe':'explorer.exe', \
							'explorer.exe':['','userinit.exe'], \
							'lsm.exe':'wininit.exe', \
							'services.exe':['wininit.exe','winlogon.exe'], \
							'csrss.exe':['', 'smss.exe']}
			
				if process[1] in parents:
					parent = parents[process[1]]
					ppid = process[3]
					if ppid in self.procids:
						if not self.procids[ppid] in parent:
							print '[!] Parent process incorrect for '+process[1]+ \
								' ('+ppid+': '+self.procids[ppid]+')'
					else:
						# The parent process is not running
						if parent != '':
							print '[!] Parent process incorrect for '+process[1]+ \
								' ('+ppid+': no parent running)'

		else:
			print '[!] Process listings not found'
			
	# Function to process the output file for the connscan plugin		
	def process_connscan(self):

		# Confirm the output files of the pstree plugin exist
		if os.path.isfile(args.image+"_volatility_connscan.txt"):

			# Normalise, combine and analyse network connections
			print '[i] Checking network connections...'
			net = []

			f = open(args.image+"_volatility_connscan.txt")
			for l in f:
				volatility = re.search(\
				"(0x[0-9a-f]+?)[ ]+([0-9\.]+?):([0-9]+)[ ]+([0-9\.]+?):([0-9]+)[ ]+([0-9]+)", l)

				if volatility:
					try:
						vol = []
						vol.append(volatility.group(1)) # 0 hex
						vol.append(volatility.group(2)) # 1 src ip
						vol.append(volatility.group(3)) # 2 src port
						vol.append(volatility.group(4)) # 3 dst ip
						vol.append(volatility.group(5)) # 4 dst port
						vol.append(volatility.group(6)) # 5 pid
						net.append(vol)
					except:
						continue
					
			self.history = []
			for self.connection in net:

				# Check for external IP address
				internal = False
				self.ip = self.connection[3]

				if '1.0.0.0' in self.ip: internal = True
				if self.ip.startswith('10.'): internal = True
				for i in range(16,32):
					if self.ip.startswith('172.'+str(i)+'.'): internal = True
				if self.ip.startswith('172.168.'): internal = True 
				if self.ip.startswith('0.'): internal = True
				if self.ip.startswith('127.'): internal = True
				if self.ip.startswith('128.0.'): internal = True
				if self.ip.startswith('169.254.'): internal = True
				if self.ip.startswith('191.255.'): internal = True
				if self.ip.startswith('192.0.0.'): internal = True
				if self.ip.startswith('223.255.255.'): internal = True

				if not internal:
					service = self.procids[self.connection[5]]
					print '[!] External connection - '+service+ \
							' ('+self.connection[5]+') to ' +self.connection[3]+':'+ \
									self.connection[4]
					
					if 'svchost.exe' in service and self.ip not in self.history:
						self.svchost_external()
						
		else:
			print '[!] Connection listings not found'
						
	# Function to process svchost with external connections event					
	def svchost_external(self):					
		self.history.append(self.ip)
		print '[!] svchost.exe connecting externally'
		
		pid = self.connection[5]
		child_procs = self.get_child_processes(pid)
		dlllist = self.dump_dlls(child_procs)
		self.sophos_scan(dlllist)
		self.vt_scan(dlllist)
	
	# Function to get child processes for given PID	
	def get_child_processes(self, pid):
		print '[-] Getting child processes'
		child_procs = []
		child_procs.append(pid)
		for i, proc in enumerate(self.procs):
			# find svchost PID in process tree
			if proc[2] == pid:
				level = len(proc[0].split(' ')[0])
				while True:
					i += 1
					try: level_next = len(self.procs[i][0].split(' ')[0])
					except: break
					if level_next > level:
						print '[-] Found', self.procs[i][1], self.procs[i][2]
						child_procs.append(self.procs[i][2])
		return child_procs
	
	# Function to dump DLLs from given list	
	def dump_dlls(self, to_dump):
		print '[-] Dumping associated dlls'
		lookup = ""
		for pid in to_dump:
			cmd = 'python2.7 vol.py' + \
					' -f ' + self.path_raw + \
					' --profile=' + self.profile + \
					' --kdbg=' + self.kdbg + \
					' dlldump -p ' +pid + \
					' --dump-dir binaries/'
			cmd = cmd.split(' ')
			proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,\
				stderr=subprocess.PIPE)
			out = proc.stdout.read()
			lookup += out
		return lookup
		
	# Function to scan binaries dir with Sophos AV
	def sophos_scan(self, lookup):
		print '[-] Performing Sophos AV scan'	
		proc = subprocess.Popen(['sweep','binaries/'], stdout=subprocess.PIPE,\
				stderr=subprocess.PIPE)
		out = proc.stdout.read()
		alerts = re.findall('>>> Virus.*', out)	
	
		for alert in alerts:
			print '[!]', alert.replace('>>> ',''),
			match = re.search('binaries/(.*)', alert)
			if match: 
				match = re.search(".*"+match.group(1)+".*", lookup)
				if match: 
					print "("+match.group(0).strip().split()[3]+")"
		
	# Function to lookup hashes on VirusTotal			
	def vt_scan(self, lookup):
		
		# Hash binaries
		lookup_table = []
		f = open('binaries/lookup_sha256.txt','w')
		filenames = glob.glob("binaries/*")
		for filename in filenames:
			real_filename = ""
			match = re.search(".*"+filename.replace('binaries/','')+".*", lookup)
			if match: real_filename = match.group(0).strip().split()[3]
			lookup_table.append([filename, real_filename, self.sha256(filename)])
			f.write(self.sha256(filename)+'\n')
		f.close()
	
		api_key = '<insert here>'
	
		print '[-] Performing VT lookup - this will take some time'
		proc = subprocess.Popen(['python2.7','virustotal-search.py','-k',api_key, \
			'binaries/lookup_sha256.txt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out = proc.stdout.read()
	
		# Writing results to disk
		f = open('vt_results.csv','w')
		for line in out:
			f.write(line)
		f.close()
	
		# Process detections
		res = open("vt_results.csv","r")
		for result in res:
			if 'requested resource' not in result:
				detections = int(result.split(';')[4])
				if detections > 4:
					hash = result.split(';')[0]
					file = ""
					for entry in lookup_table:
						if hash in entry[2]:
							file = entry[1]
							dl = entry[0]
					print '[!] '+hash+' ('+file+' - '+dl+'), Detections: '+ \
						str(detections)

# main()
if __name__ == '__main__':

	# Handle command line arguments and usage/help
	parser = argparse.ArgumentParser()
	parser.add_argument('image', help='machine identifier for processing')
	args = parser.parse_args()
	
	# Run Volatility
	vol_process(args.image).run_v()
