#!/usr/bin/env python3
import copy
from sys import argv
#from string import ljust
file_opened = open('xx.txt', 'r')
#file_write = open('y.txt', 'w')

#
#
#
#PART ONE, where we normalize our ACL entries 
#
#
#

counter = 0
lines_reassembled = []

portnames = {'bgp':'179','chargen':'19','cmd':'rcmd, 514','daytime':'13','discard':'9','domain':'53','drip':'3949','echo':'7','exec':'512','finger':'79','ftp':'21','ftp-data':'20','gopher':'70','hostname':'101','ident':'113','irc':'194','klogin':'543','kshell':'544','login':'rlogin, 513','lpd':'515','nntp':'119','pim-auto-rp':'496','pop2':'109','pop3':'110','smtp':'25','sunrpc':'111','tacacs':'49','talk':'517','telnet':'23','time':'37','uucp':'540','whois':'43','www':'80', 'ntp':'123', 'snmp':'161', 'snmptrap':'162', 'bootpc':'68', 'bootps':'67'}

def wildcard_converter(wildcard):
	wildcard_bin = ''
	wildcard_disassembled = wildcard.split('.')
	for octet in wildcard_disassembled:
		wildcard_bin = wildcard_bin + format(int(octet), "08b")	
	return str(wildcard_bin.count('0'))
	

for line in file_opened:
	line = line.strip()
	if 'permit' in line:
		line = line[line.find('permit'):]
		print(line + '!')
	else:
		line = line[line.find('deny'):]
		print(line)
	lines_reassembled.append('')
	lines_reassembled[counter] = {}
	line_split = line.split(' ')
	lines_reassembled[counter]['action'] = line_split[0]
	lines_reassembled[counter]['protocol'] = line_split[1]
	
#source	address and mask
	if line_split[2] == 'host':
		lines_reassembled[counter]['src_ip'] = line_split[3]
		lines_reassembled[counter]['src_mask'] = '32'
	elif '/' in line_split[2]:
		lines_reassembled[counter]['src_ip'] = line_split[2].split('/')[0]
		lines_reassembled[counter]['src_mask'] = line_split[2].split('/')[1]
		#to keep our list of a same length			
		line_split.insert(3, '_srcmask')
	elif line_split[2] == 'any':
		lines_reassembled[counter]['src_ip'] = '0.0.0.0'
		lines_reassembled[counter]['src_mask'] = '0'
		line_split.insert(3, '_srcmask')
	else:
		lines_reassembled[counter]['src_ip'] = line_split[2]
		lines_reassembled[counter]['src_mask'] = wildcard_converter(line_split[3])	
		
#source port	
#single port	
	if 	line_split[4] == 'eq':
		if line_split[5] in portnames.keys():
			lines_reassembled[counter]['src_port_1'] = portnames[line_split[5]]
			lines_reassembled[counter]['src_port_2'] = portnames[line_split[5]]
			line_split.insert(6, '_srcport')
		else:
			lines_reassembled[counter]['src_port_1'] = line_split[5]
			lines_reassembled[counter]['src_port_2'] = line_split[5]
			line_split.insert(6, '_srcport')
#range			
	elif line_split[4] == 'range':		
		if line_split[5] in portnames.keys():
			lines_reassembled[counter]['src_port_1'] = portnames[line_split[5]]
		else:
			lines_reassembled[counter]['src_port_1'] = line_split[5]			
		if line_split[6] in portnames.keys():
			lines_reassembled[counter]['src_port_2'] = portnames[line_split[6]]
		else:
			lines_reassembled[counter]['src_port_2'] = line_split[6]		

#gt

	elif line_split[4] == 'gt':
		if line_split[5] in portnames.keys():
			lines_reassembled[counter]['src_port_1'] = portnames[line_split[5]]
			lines_reassembled[counter]['src_port_2'] = '65535'
		else:
			lines_reassembled[counter]['src_port_1'] = str(int(line_split[5]) + 1)
			lines_reassembled[counter]['src_port_2'] = '65535'
		line_split.insert(6, '_srcport')
			
#or maybe theres no port at all? 		
	else:
		line_split.insert(4, '_srcport')
		line_split.insert(5, '_srcport')
		line_split.insert(6, '_srcport')
		lines_reassembled[counter]['src_port_1'] = '0'
		lines_reassembled[counter]['src_port_2'] = '0'
		

#dst address and mask			
	if line_split[7] == 'host':
		lines_reassembled[counter]['dst_ip'] = line_split[8]
		lines_reassembled[counter]['dst_mask'] = '32'
	elif '/' in line_split[7]:
		lines_reassembled[counter]['dst_ip'] = line_split[7].split('/')[0]
		lines_reassembled[counter]['dst_mask'] = line_split[7].split('/')[1]
		line_split.insert(8, '_dstport')
	elif line_split[7] == 'any':
		lines_reassembled[counter]['dst_ip'] = '0.0.0.0'
		lines_reassembled[counter]['dst_mask'] = '0'
		line_split.insert(8, '_dstmask')		
	else:
		lines_reassembled[counter]['dst_ip'] = line_split[7]
		lines_reassembled[counter]['dst_mask'] = wildcard_converter(line_split[8])	
	
#dst port	
#we have to use try cause in case theres no dst port, our index [9] will be out of range
	try:
#single port	
		if 	line_split[9] == 'eq':
			if line_split[10] in portnames.keys():
				lines_reassembled[counter]['dst_port_1'] = portnames[line_split[10]]
				lines_reassembled[counter]['dst_port_2'] = portnames[line_split[10]]
			else:
				lines_reassembled[counter]['dst_port_1'] = line_split[10]
				lines_reassembled[counter]['dst_port_2'] = line_split[10]	
			line_split.insert(11, '_dstport')
#range			
		elif line_split[9] == 'range':		
			if line_split[10] in portnames.keys():
				lines_reassembled[counter]['dst_port_1'] = portnames[line_split[10]]
			else:
				lines_reassembled[counter]['dst_port_1'] = line_split[10]			
			if line_split[11] in portnames.keys():
				lines_reassembled[counter]['dst_port_2'] = portnames[line_split[11]]
			else:
				lines_reassembled[counter]['dst_port_2'] = line_split[11]		

#gt

		elif line_split[9] == 'gt':
			if line_split[10] in portnames.keys():
				lines_reassembled[counter]['dst_port_1'] = portnames[line_split[10]]
				lines_reassembled[counter]['dst_port_2'] = '65535'
			else:
				lines_reassembled[counter]['dst_port_1'] = str(int(line_split[10]) + 1)
				lines_reassembled[counter]['dst_port_2'] = '65535'
			line_split.insert(11, '_dstport')
				
#or maybe theres no port at all? 		
	except IndexError:
		line_split.insert(9, '_dstport')
		line_split.insert(10, '_dstport')
		line_split.insert(11, '_dstport')
		lines_reassembled[counter]['dst_port_1'] = '0'
		lines_reassembled[counter]['dst_port_2'] = '0'	
		
#	print(line_split)
#	print(lines_reassembled[counter])
	counter = counter + 1
	
#
#
#
#PART TWO, where we destroy overlapping address/mask entries like these
#
#
#

#first day at my new cybersecurity engineer position
#210 permit tcp any 10.99.111.44 0.0.0.1 eq 135
#220 permit tcp any 10.99.111.44 0.0.0.1 eq 1688
#490 permit ip 10.12.188.0 0.0.1.255 10.99.111.2/32
#500 permit ip 10.12.188.0 0.0.1.255 10.99.111.3/32

#6th month at my cybersecurity engineer position
#1280 permit ip any 10.99.111.0 0.0.0.127
#1290 permit ip any 10.99.111.128 0.0.0.127  

#for both mask and ip
def ip_converter(ip_addr):
	ip_bin = ''
	ip_disassembled = ip_addr.split('.')
	for octet in ip_disassembled:
		ip_bin = ip_bin + format(int(octet), "08b")	
	return ip_bin
	
def bin_to_ip_converter(ip_addr):
	ip_addr = ip_addr.ljust(32, '0')
	octet_0, octet_1, octet_2, octet_3 = ip_addr[0:8], ip_addr[8:16], ip_addr[16:24], ip_addr[24:32]
	return str(int(octet_0, 2)) + '.' + str(int(octet_1, 2)) + '.' + str(int(octet_2, 2)) + '.' + str(int(octet_3, 2))


counter_a = 0
copy_lr = copy.deepcopy(lines_reassembled)
#we are comparing our original(o) list with a copy(c), deleting overlapping entries from the original one
for a in lines_reassembled:	
	for b in copy_lr:
		if a == b:			
			continue			
#to consider an entry overlapped following conditions should be met:
#((dst ip and mask(o) == dst ip and mask(c)) OR (dst mask(o) >= dst mask(c) and dst ip(o) with mask of dst ip(c) applied == dst ip(c) with mask of dst ip(c) applied )) AND
#((src ip and mask(o) == src ip and mask(c)) OR (src mask(o) >= src mask(c) and src ip(o) with mask of src ip(c) applied == src ip(c) with mask of src ip(c) applied )) AND
#dst port(o) == dst port(c)	or dst port(c) == any AND
#src port(o) == src port(c)	or src port(c) == any AND
#protocol(o) == protocol(c) OR protocol(c) == ip
		elif(((int(a['dst_mask']) >= int(b['dst_mask'])) and (ip_converter(a['dst_ip'])[0:int(b['dst_mask'])] == ip_converter(b['dst_ip'])[0:int(b['dst_mask'])]))and 
		((int(a['src_mask']) >= int(b['src_mask'])) and (ip_converter(a['src_ip'])[0:int(b['src_mask'])] == ip_converter(b['src_ip'])[0:int(b['src_mask'])])) and 
		((a['dst_port_1'] == b['dst_port_1'] and a['dst_port_2'] == b['dst_port_2']) or (b['dst_port_1'] == '0' and b['dst_port_2'] == '0')) and 
		((a['src_port_1'] == b['src_port_1'] and a['src_port_2'] == b['src_port_2']) or (b['src_port_1'] == '0' and b['src_port_2'] == '0')) and
		(a['protocol'] == b['protocol'] or b['protocol'] == 'ip') and a['action'] == b['action']):		
			print('We are now deleting this line:')
			print(a['action'] + ' ' +a['protocol'] + ' ' + a['src_ip']  + '/' + a['src_mask'] + ' ports ' + a['src_port_1'] + ' ' + a['src_port_2']+   ' ' +  a['dst_ip'] + '/' + a['dst_mask'] + ' ports ' + a['dst_port_1'] + ' ' + a['dst_port_2'])
			print('because it overlaps with this line')
			print(b['action'] + ' ' + b['protocol'] + ' ' + b['src_ip']  + '/' + b['src_mask'] + ' ports ' + b['src_port_1'] + ' ' + b['src_port_2']+   ' ' +  b['dst_ip'] + '/' + b['dst_mask'] + ' ports ' + b['dst_port_1'] + ' ' + b['dst_port_2'] + '\r\n...')
			lines_reassembled[counter_a] = ''
#			print(str(a))
#			print(str(b))
		else:
			continue
	counter_a = counter_a + 1	
	
			
#cleaning up
while ('' in lines_reassembled): 
    lines_reassembled.remove('') 



#this part here is to try and combine entries that don't overlap but _can_ be combined, like 192.168.0.0/32 and 192.168.0.1/32 to 192.168.0.0/31
#the tricky thing about this is the fact i only check one entry at time, while there can be more than one entry to combine
#like 192.168.0.0/32, 192.168.0.1/32, 192.168.0.2/32 and 192.168.0.4/32. to solve this i'm just running the cycle several times
#so for some huge hardcore ACLs there's a chance some entries will not be optimized completely


#dst ip
for x in range(0,5):
	counter_a = 0
	counter_b = 0
	copy_lr = copy.deepcopy(lines_reassembled)
	for a in lines_reassembled:	
		counter_b = 0
		for b in copy_lr:
			if a == b or a == '' or b == '':	
				counter_b +=1
				continue	
			elif (a['dst_mask'] == b['dst_mask'] and a['src_ip'] == b['src_ip'] and a['src_mask'] == b['src_mask'] and a['protocol'] == b['protocol'] and (ip_converter(a['dst_ip'])[0:(int(b['dst_mask']) - 1)] == ip_converter(b['dst_ip'])[0:(int(b['dst_mask']) - 1)]) and (a['dst_port_1'] == b['dst_port_1'] and a['dst_port_2'] == b['dst_port_2']) and (a['src_port_1'] == b['src_port_1'] and a['src_port_2'] == b['src_port_2'])):
				print('We are now replacing this line')
				print(a['action'] + ' ' +a['protocol'] + ' ' + a['src_ip']  + '/' + a['src_mask'] + ' ports ' + a['src_port_1'] + ' ' + a['src_port_2']+   ' ' +  a['dst_ip'] + '/' + a['dst_mask'] + ' ports ' + a['dst_port_1'] + ' ' + a['dst_port_2'])
				print('because it overlaps with this line:')
				print(b['action'] + ' ' + b['protocol'] + ' ' + b['src_ip']  + '/' + b['src_mask'] + ' ports ' + b['src_port_1'] + ' ' + b['src_port_2']+   ' ' +  b['dst_ip'] + '/' + b['dst_mask'] + ' ports ' + b['dst_port_1'] + ' ' + b['dst_port_2'])
				print('...and are instead creating entry with network: ' + bin_to_ip_converter(ip_converter(a['dst_ip'])[0:(int(b['dst_mask']) - 1)]) + ' and mask: ' + str(int(a['dst_mask']) - 1))
				print('..We also delete this line:')
				print(b['action'] + ' ' + b['protocol'] + ' ' + b['src_ip']  + '/' + b['src_mask'] + ' ports ' + b['src_port_1'] + ' ' + b['src_port_2']+   ' ' +  b['dst_ip'] + '/' + b['dst_mask'] + ' ports ' + b['dst_port_1'] + ' ' + b['dst_port_2'] + '\r\n...')
				lines_reassembled[counter_a]['dst_mask'] = str(int(a['dst_mask']) - 1)
				lines_reassembled[counter_a]['dst_ip'] = bin_to_ip_converter(ip_converter(a['dst_ip'])[0:(int(b['dst_mask']) - 1)])
				lines_reassembled[counter_b] = ''
			else:
				counter_b += 1
				continue
		counter_a +=1

		
#cleaning up
while ('' in lines_reassembled): 
    lines_reassembled.remove('') 
	
for x in range(0,5):
	counter_a = 0
	counter_b = 0
	copy_lr = copy.deepcopy(lines_reassembled)
	for a in lines_reassembled:	
		counter_b = 0
		for b in copy_lr:
			if a == b or a == '' or b == '':	
				counter_b +=1
				continue	
			elif a['src_mask'] == b['src_mask'] and a['dst_ip'] == b['dst_ip'] and a['dst_mask'] == b['dst_mask'] and a['protocol'] == b['protocol'] and (ip_converter(a['src_ip'])[0:(int(b['src_mask']) - 1)] == ip_converter(b['src_ip'])[0:(int(b['src_mask']) - 1)]) and (a['dst_port_1'] == b['dst_port_1'] and a['dst_port_2'] == b['dst_port_2']) and (a['src_port_1'] == b['src_port_1'] and a['src_port_2'] == b['src_port_2']):			
				print('We are now replacing this line')
				print(a['action'] + ' ' +a['protocol'] + ' ' + a['src_ip']  + '/' + a['src_mask'] + ' ports ' + a['src_port_1'] + ' ' + a['src_port_2']+   ' ' +  a['dst_ip'] + '/' + a['dst_mask'] + ' ports ' + a['dst_port_1'] + ' ' + a['dst_port_2'])
				print('because it overlaps with this line:')
				print(b['action'] + ' ' + b['protocol'] + ' ' + b['src_ip']  + '/' + b['src_mask'] + ' ports ' + b['src_port_1'] + ' ' + b['src_port_2']+   ' ' +  b['dst_ip'] + '/' + b['dst_mask'] + ' ports ' + b['dst_port_1'] + ' ' + b['dst_port_2'])
				print('and are instead creating entry with network: ' + bin_to_ip_converter(ip_converter(a['src_ip'])[0:(int(b['src_mask']) - 1)]) + ' and mask: ' + str(int(a['dst_mask']) - 1))
				print('..We also delete this line:')
				print(str(lines_reassembled[counter_b]) + '\r\n...')
				lines_reassembled[counter_a]['src_mask'] = str(int(a['src_mask']) - 1)
				lines_reassembled[counter_a]['src_ip'] = bin_to_ip_converter(ip_converter(a['src_ip'])[0:(int(b['src_mask']) - 1)])
				lines_reassembled[counter_b] = ''
			else:
				counter_b += 1
				continue
		counter_a +=1
				
#cleaning up
while ('' in lines_reassembled): 
    lines_reassembled.remove('') 

print('Heres our ACL after deleting overlapping net entries')
for a in lines_reassembled:
	print(a['action'] + ' ' +a['protocol'] + ' ' + a['src_ip']  + '/' + a['src_mask'] + ' ports ' + a['src_port_1'] + ' ' + a['src_port_2']+   ' ' +  a['dst_ip'] + '/' + a['dst_mask'] + ' ports ' + a['dst_port_1'] + ' ' + a['dst_port_2'] + '\r\n')
		
		
#
#
#
#PART THREE, where we concentrate on calculating how much TCAM will be consumed by port ranges and whether they can be squeezed
#
#
#

	
	

def port_range_counter(range_1, range_2):
	range_1 = int(range_1)
	range_2 = int(range_2)
	
	#modify this value in case you have different LOU configured on your switch - this is default one
	LOU_THRESHOLD = 5
	lou_threshold_change = 0
	
	#here we just calculate the largest possible mask for a defined range to start with, which will cover the largest possible number of ports #within our range, but no more. for instance, for a range 10-23 [14 ports] it will be 2^3 = 8
	def power_finder(range_1, range_2):
#		print('range1: ' + str(range_1))
#		print('range2: '+ str(range_2))
		#range_dif = simply number of ports
		range_dif = range_2 - range_1 + 1
		power = 0
#		print('START: power = ' + str(power) + '...2**power = ' + str(2**power) + '...range_dif = ' + str (range_dif))
		#while calculated mask is less than number of ports
		while 2**power <= range_dif:
#			print('BEFORE: power = ' + str(power) + '...2**power = ' + str(2**power) + '...range_dif = ' + str (range_dif))
			power = power + 1
#			print('AFTER: power = ' + str(power) + '...2**power = ' + str(2**power) + '...range_dif = ' + str (range_dif))
#		print('power_returned = ' + str((power - 1)))
		return (power - 1)
	
	tcam_counter = 0
	
	#what we are doung here is just basic CCNA calculations level stuff but with ports instead of ip addresses
	#we need to cover a certain range of ports, without covering any extra ports, so we need to calculate a combination of several masks		
	while (range_1 - 1) != range_2:
		power = power_finder(range_1, range_2)
		rem = 1
		#in here we calculate correct mask == byte range for our first port (like, remember, if you have mask of /25 you can't have 192.168.0.33 as #your network address. so we take the initial value given by power_finder and divide first port by it, decreasing the power until 
		#we'll have a remainder of zero
		while rem != 0:
			rem = range_1%(2**power)
			power = power - 1
#			print('power in WHILE: ' + str(power))
		tcam_counter += 1
		#now we've calculated a mask for the first value, replace it to calculate the rest
		range_1 = range_1 + 2**(power + 1)
#		print('power after WHILE: ' + str(power + 1))
		
	if tcam_counter > LOU_THRESHOLD:
		lou_threshold_change = 1
		tcam_counter = 1
	return [tcam_counter, lou_threshold_change]
		
		
l_usage = 0
tcam_usage = 0
lou_compressed = []
entries_fragmented = 0
list_of_entries_fragmented = []
tcam_multiplier = 1
src_ports_present = False

for a in lines_reassembled:
	tcam_multiplier = 1
	entry_fragmented = False
	src_ports_present = False
	#if we have a range of src ports
	if a['src_port_1'] != a['src_port_2']:	
		src_ports_present = True
		if (a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])not in list_of_entries_fragmented:
			entry_fragmented = True
			list_of_entries_fragmented.append(a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])
		if port_range_counter(a['src_port_1'], a['src_port_2'])[1] > 0 and (a['src_port_1'] + ':' + a['src_port_2']) not in lou_compressed:
			l_usage = l_usage + port_range_counter(a['src_port_1'], a['src_port_2'])[1]
			lou_compressed.append(a['src_port_1'] + ':' + a['src_port_2'])
			tcam_usage = tcam_usage + port_range_counter(a['src_port_1'], a['src_port_2'])[0]
			tcam_multiplier = port_range_counter(a['src_port_1'], a['src_port_2'])[0]
#			print('tcam multiplier is ' + str(tcam_multiplier))
#			print('port range counter is ' + str(port_range_counter))
		else:
			tcam_usage = tcam_usage + port_range_counter(a['src_port_1'], a['src_port_2'])[0]	
			tcam_multiplier = port_range_counter(a['src_port_1'], a['src_port_2'])[0]
#			print('tcam usage after counting src ports: ' + str(tcam_usage))
#			print('tcam multiplier: ' + str(tcam_multiplier))
			
	#if we have a range of dst ports
	if a['dst_port_1'] != a['dst_port_2']:
		if (a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])not in list_of_entries_fragmented:
			entry_fragmented = True
			list_of_entries_fragmented.append(a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])
		if port_range_counter(a['dst_port_1'], a['dst_port_2'])[1] > 0 and (a['dst_port_1'] + ':' + a['dst_port_2']) not in lou_compressed:
			l_usage = l_usage + port_range_counter(a['dst_port_1'], a['dst_port_2'])[1]
			lou_compressed.append(a['dst_port_1'] + ':' + a['dst_port_2'])
			tcam_usage = tcam_usage + tcam_multiplier*port_range_counter(a['src_port_1'], a['src_port_2'])[0]
			tcam_multiplier = port_range_counter(a['dst_port_1'], a['dst_port_2'])[0]
		else:
			#if there's both src AND dst ports we should multilpy expansion ranges instead of adding them, so..i just substract src range I added before cause I noticed it way too late and am too lazy to implement it gracefully
			if src_ports_present:
				tcam_usage = tcam_usage - port_range_counter(a['src_port_1'], a['src_port_2'])[0] + tcam_multiplier*port_range_counter(a['dst_port_1'], a['dst_port_2'])[0]
			else:
				tcam_usage = tcam_usage + tcam_multiplier*port_range_counter(a['dst_port_1'], a['dst_port_2'])[0]			
				tcam_multiplier = port_range_counter(a['dst_port_1'], a['dst_port_2'])[0]
			
	#if theres single src port
	if a['src_port_1'] == a['src_port_2'] != '0':
		src_ports_present = True
		if (a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])not in list_of_entries_fragmented:
			entry_fragmented = True
			list_of_entries_fragmented.append(a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])
		tcam_usage = tcam_usage + tcam_multiplier*1
	
	#if theres single dst port
	if a['dst_port_1'] == a['dst_port_2'] != '0':	
		if (a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])not in list_of_entries_fragmented:
			entry_fragmented = True
			list_of_entries_fragmented.append(a['protocol'] + ':' + a['src_ip'] + ':' + a['src_mask'] + ':' + a['dst_ip'] + ':' + a['dst_mask'])
		#if there's range of SRC ports we should multilpy expansion ranges instead of adding them, so..i just substract src range I added before cause I noticed it way too late and am too lazy to implement it gracefully. also this will prevent us from adding extra entries for entries where there are both src and dst port			
		if src_ports_present:
			tcam_usage = tcam_usage - port_range_counter(a['src_port_1'], a['src_port_2'])[0] + tcam_multiplier*port_range_counter(a['dst_port_1'], a['dst_port_2'])[0]
		else:
			tcam_usage = tcam_usage + tcam_multiplier*1
			
#		print('tcam usage raw...' + str(tcam_usage + entries_fragmented))
#		print('tcam multiplier...' + str(tcam_multiplier))

	#if theres no ports at all
	if a['dst_port_1'] == a['dst_port_2'] == a['src_port_1'] == a['src_port_2'] == '0':
		tcam_usage +=1
	
	#additional entry is consumed in case of fragmentation
	if entry_fragmented:
		entries_fragmented += 1
		print('This line is fragmented and will consume an additional TCAM entry')

		
	print('After adding this line')
	print(a['action'] + ' ' +a['protocol'] + ' ' + a['src_ip']  + '/' + a['src_mask'] + ' ports ' + a['src_port_1'] + ' ' + a['src_port_2']+   ' ' +  a['dst_ip'] + '/' + a['dst_mask'] + ' ports ' + a['dst_port_1'] + ' ' + a['dst_port_2'])
	print('we are now having total TCAM consumption of ' + str(tcam_usage + entries_fragmented) + '\r\n...')

tcam_usage += entries_fragmented		
		
print('Total TCAM usage = ' + str(tcam_usage))
print('Including fragmented entries = ' + str(entries_fragmented))
print('LOU usage = ' + str(l_usage))		

file_opened.close()
	
	
	
