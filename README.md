# dnsx
Socksifying DNS Daemon for OSX / BSD, based on http://www.mulliner.org/collin/ttdnsd.php

You can can run this daemon on localhost and point your DNS setting to it. 
DNS Requests will be relayed through a Socks connection that you can specify
with a config file. 

Some options for the Socks daemon are:
- ssh
- tor

The relayed DNS requests are finally resolved by DNS Servers that support DNS over TCP.
OpenDNS provides such servers, two of which are readily configured in another config file.


### Building
make

### Running
    syntax: dnsx [bpfPCcdlhV]
      -b  <server ip> server IP to bind
      -p  <server port> server port to bind
      -f  <nameservers> filename to read nameserver IP(s) from
      -P  <PID file>  file to store process ID - pre-chroot
      -C  <chroot dir>  chroot(2) to <chroot dir>
      -c      DON'T chroot(2) to /var/lib/dnsx
      -d      become a daemon
      -t      path to tsocks.conf file
      -h      print this helpful text and exit
      -V      print version and exit

    export TSOCKS_CONF_FILE to point to config file inside the chroot
