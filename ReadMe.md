-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
            
             SSH Man In The Middle tool
             Copyright (C) 2005 Claes M Nyberg <cmn@signedness.org.com>

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


--[ Disclamer

  This tool is for educational purposes ONLY and is not intented to be used
  for illegal purposes. The author is not responsible for any damage which
  this tool might cause.


--[ What is this?

  This is a tool for performing Man In The Middle attacks against SSH 1 & 2.
  It is based on OpenSSH 3.9p1, credits to the authors of OpenSSH.

  The tool listens on port 22 by default and redirects connecting clients to 
  the address specified on the command line unless they are behind NAT 
  (or the victims of an ARP poisoning attack, which is pretty much the same thing).
  If clients are NATed they are redirected to the real target instead of
  the 'static route' given on the command line.
  
  Passwords and data transfered are logged, look at mitm-ssh_config
  for details.


--[ MITM setup
  
  There are a couple of ways to re-route clients to your machine and make it 
  possible to set up an unencrypted gap between the client and the real server. 
  
  One way is to respond faster than the target DNS server to a DNS query, 
  and theirby controlling the IP address that the client will connect to 
  if a hostname is entered rather than an IP address. 
  
  This is convinient if data sent to a specific machine is of interest (such 
  as a webmail service or the machine that wireless clients enter their 
  username and passwords on to get an Internet connection), but makes it hard 
  to find out where the clients really want to go in the general case since most 
  protocols do not carry this information. It works great for HTTPS though, 
  since 'Host:' is set by most browsers.

  Another way is to send fake ARP replys and overwrite the hardware address
  of a given IP in the ARP table. By replacing the hardware address of the
  gateway with the address of your machine, you become the gateway for the
  clients receiving the fake ARP reply. 
  The nice thing with this method is that you can easily find out where
  the client really wants to go by sniffing for SYN packets to the port
  of the service that you are intercepting since nothing is changed in
  the headers except for the hardware address.

  You only have to set up IPv4 forwarding and port forward the service 
  that you are attacking to the MITM tool which will connect to the real 
  target and scan for passwords in the data transmitted by the client.
  
  On Linux:
  echo 1 > /proc/sys/net/ipv4/ip_forward
  iptables -tnat -A PREROUTING -p tcp --dport<port> -i<iface> -jDNAT --to<host>:<port>


--[ Compile and install
  ./configure && make install


--[ TODO

  o X11 forwarding
  o Scan channel data for passwords
  o Public key authentication


Have Fun, and behave :-)

/C <cmn@signedness.org>

