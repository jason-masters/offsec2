# test2_ochoa-2010-0209.rb
# Windows SMB NTLM Authentication Weak Nonce Vulnerability detection script
# This script will run in an infinite loop looking for duplicate challenges displaying a message
# every time one is received.
# (c) 2010 Hernan Ochoa (hernan@ampliasecurity.com)
 
require 'socket'
 
chs = []
attempts = 0
host = ""
port = 445
challenges_filename = "challenges.log"
duplicates_filename = "duplicates.log"
 
 
    print "This script tests for the Windows SMB NTLM Authentication Weak Nonce Vulnerability\n"
    print "(c) 2010 Hernan Ochoa (hernan@ampliasecurity.com)\n" 
 
    if ARGV.size < 1 then
        print "syntax: test2_ochoa-2010-0209.rb <host>\n"
        exit
    end
 
    host = ARGV[0]
     
    print "Testing host " + host + "\n"
 
    neg_proto_packet_1 = 
    "00000054" +
    "ff534d4272000000001801c00000000000000000000000000000866100005480003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200"
 
 
    if File.file?( challenges_filename ) then
        File.delete( challenges_filename )
    end
 
    if File.file?( duplicates_filename ) then
        File.delete( duplicates_filename )
    end
 
loop do
    so = TCPSocket.open(host, port)
    attempts = attempts + 1
 
    n = neg_proto_packet_1.scan(/../).map { |s| s.to_i(16) }
    j = n.pack("C*")
    so.write(j)
    resp = so.recvfrom(2000)
 
    j = resp.to_s[0x49..0x49+7]
    vuelta = j
 
 
    test = j.unpack("C*").map { |v|  ("%.2x" % (v)).chomp }
    challenge = test.to_s
 
    so.close
 
    File.open( challenges_filename , "a" ) { |f| f.write(challenge+"\n") }
 
    if chs.include? challenge 
            puts "duplicate found!\a\a\a\a\a\a\a\a\a\a\a\a\n"
        ndx = chs.index(challenge)
        print "request #" + attempts.to_s + ", challenge=" + challenge + "\n"
        print "request #" + (ndx+1).to_s +  ", challenge=" + chs[ndx] + "\n"
        File.open( duplicates_filename , "a") { |f| f.write(challenge+"\n") }   
    end
 
    chs.push(challenge)
 
end
