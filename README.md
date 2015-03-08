`utdnsd`, a DNS forwarder serving requests from UDP clients by delegating them to upstream DNS servers with TCP.  The idea is from `ttdnsd` of Tor Project.

OpenWrt package definition files can be found at [waller repository](https://github.com/yousong/waller); detailed instructions of how to import them should be included there.

## Build

[`libubox`](http://git.openwrt.org/?p=project/libubox.git;a=summary) from OpenWrt project is required.  On Mac OS X with MacPorts installed, you can get `libubox` installed by using portfiles from [macports-openwrt repository](https://github.com/yousong/macports-openwrt).

To build it locally (of course, CMake is required here).

	cmake . && make

To configure the build (mainly the `DEBUG` option).

	ccmake .

## Run.

When run without arguments, help text will be printed to stderr.

	yousong@yousongs-MacBook-Air:~/dev/utdnsd$ ./utdnsd 
	Usage: utdnsd [ -qh ] -l <host[:port]> [ -s <host[:port]> ... ] [ -t <seconds> ]
	  -l <host[:port]>  Address and port to listen to.
	  -s <host[:port]>  Upstream DNS server we ask for service through TCP transport.
	  -t <seconds>      Maximum delay for reconnect attempts (defaults to 5s).
	  -T <seconds>      Maximum delay before the link was considered shoddy (defaults to 5s).
	  -q                Be quiet.
	  -h                This output.

Currently, at most 8 `-s <host:[port]>` can be specified on the command line.  Same upstream server can be specified multiple times with the `-s` option.

Example run.

	yousong@yousongs-MacBook-Air:~/dev/utdnsd(master)$ ./utdnsd -l 127.0.0.1:8053 -s 202.130.97.66 -s 202.180.160.1 -s 203.91.143.19 -s 202.130.97.65 -s 202.174.131.19 -s 202.181.224.2 -s 202.45.84.58 -s 202.84.255.1 
	info: connect to 202.130.97.66:53 succeeded.
	info: connect to 202.180.160.1:53 succeeded.
	info: connect to 203.91.143.19:53 succeeded.
	info: connect to 202.130.97.65:53 succeeded.
	info: connect to 202.174.131.19:53 succeeded.
	info: connect to 202.181.224.2:53 succeeded.
	info: connect to 202.45.84.58:53 succeeded.
	info: connect to 202.84.255.1:53 succeeded.
	info: start serving!
	== SIGUSR1 received, statistics follows
	>   202.130.97.66:53   state:1 reconn:0   served:42    staging:0   estimate:0  wbuf:0   rbuf:0   sent:1470     recv:13356   
	>   202.180.160.1:53   state:1 reconn:0   served:9     staging:0   estimate:0  wbuf:0   rbuf:0   sent:315      recv:2367    
	>   203.91.143.19:53   state:1 reconn:0   served:9     staging:0   estimate:0  wbuf:0   rbuf:0   sent:315      recv:2367    
	>   202.130.97.65:53   state:1 reconn:0   served:42    staging:0   estimate:0  wbuf:0   rbuf:0   sent:1470     recv:11046   
	>  202.174.131.19:53   state:1 reconn:0   served:11    staging:0   estimate:0  wbuf:0   rbuf:0   sent:385      recv:3018    
	>   202.181.224.2:53   state:1 reconn:0   served:35    staging:0   estimate:0  wbuf:0   rbuf:0   sent:1225     recv:9205    
	>    202.45.84.58:53   state:1 reconn:0   served:28    staging:0   estimate:0  wbuf:0   rbuf:0   sent:980      recv:7364    
	>    202.84.255.1:53   state:1 reconn:0   served:19    staging:0   estimate:0  wbuf:0   rbuf:0   sent:665      recv:6061    
	=================== statistics ends

As you can see from the above output, sending `SIGUSR1` to `utdnsd` will cause it to print some statistics.

## Quirks

Below are some different strategies or situations I came across while doing testing against a varieties of public DNS servers.

- Only 1 query per TCP connection.  Disconnect at the end of that transaction.

		114.114.114.114

- EOF at EOC (end of connection).  But at least one request can be served before that `RST`.  Not sure the strategy is from the original DNS service provider, or some intermediate firewall thingy.

		8.8.8.8

- Only 1 connection per IP (this is a guess), other connections may hang or delay with `ACK`, `ACK`, ...

## Tips

If you have got a long list of usable DNS servers and in a decidophobia as to which ones to use.  Then some randomness can help.

	server_list='hk.txt.1'

	total="$(wc -l "$server_list" | awk '{ print $1; }')"
	[ "$total" -gt "8" ] && {
		total="$(( $total - 8 ))"
		pos="$(( $RANDOM % $total ))"
		servers="$(sed -n "$pos,$(($pos+7))p" "$server_list")"
	} || {
		servers="$(cat "$server_list")"
	}

	sopts=""
	for s in $servers; do
			sopts="$sopts -s $s"
	done
	./utdnsd -l 127.0.0.1:8053 $sopts

Test it with `dig`, `nslookup`.

	dig -p 8053 @127.0.0.1 www.openvpn.net
	nslookup www.openvpn.net 127.0.0.1 -port=8053
	nslookup www.openvpn.net 127.0.0.1:8053

## TODO

- A list of domain names from browser history for testing purposes.
- Workaround the issue with `8.8.8.8`.

	- Add a global staging area for requests that cannot be served immediately.
	- Move interrupted sessions to the staging area.
	- Serve that staging area once reconnect is successful.

	The problem being when and how much to write staged requests?

	- ALL?
	- Add a uloop for writable TCP fd monitor.

- When to stop reading in requests and do the actual service.
- More than NSERVERS upstream TCP servers and HEAP style.

## Resources

- adns, mainly as a resolver library, http://www.chiark.greenend.org.uk/~ian/adns/
- ttdnsd from Tor project, https://gitweb.torproject.org/ioerror/ttdnsd.git
- DNS benchmark using web browser history, tcpdump output, etc.. https://code.google.com/p/namebench/

	- Cannot specify port number.
	- Looks nice but got loads of complaints.

- dnsperf, http://nominum.com/measurement-tools/
- DNS benchmark tool for Windows, https://www.grc.com/dns/benchmark.htm
- Public DNS Server List, http://public-dns.tk/
- Public DNS services
	- Google DNS
	- OpenDNS
	- V2EX DNS, https://v2ex.com/go/dns
