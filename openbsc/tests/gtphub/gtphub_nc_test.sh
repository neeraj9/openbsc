#!/usr/bin/env bash
# gtphub_nc_test.sh

# TODO does this work with all relevant netcat implementations?
# TODO skip if netcat not found?
# TODO use only 127.0.0.1 once gtphub is configurable.

gtphub_bin="./osmo-gtphub"
if [ ! -x "$gtphub_bin" ]; then
	echo "executable not found: $gtphub_bin"
	exit 1;
fi

#  client              osmo-gtphub                            gtp server
#  127.0.0.1:9876 <--> 127.0.0.1:21231 | 127.0.0.1:21232 <--> 127.0.0.1 2123
#  (netcat)            ($gtphub_bin)                          (netcat)

# start gtphub relay
"$gtphub_bin" -c gtphub.conf &
sleep 0.1

# log what reaches client and server
nc --recv-only -u -l -p 9876 -s 127.0.0.1 > recv_client &
nc --recv-only -u -l -p 2123 -s 127.0.0.1 > recv_server &
sleep .1

# send test messages, both ways.
# 's1' is sequence nr 1, 'm1' is mapped seq 1 (see gtphub_peer_new()),
# and yes, the 's1' characters are "coincidentally" at just the right spot.
msg1="(msg 1: s1 client to server)"
msg1_expect="(msg 1: m1 client to server)"
echo "$msg1" | nc --send-only -u -s 127.0.0.1 -p 9876 127.0.0.1 21231

# server sends reply with the mapped sequence nr., but wrong sender in terms of
# the configured GGSN proxy address.
msgx="(msg x: m1 server to client to be rejected)"
echo "$msgx" | nc --send-only -u -s 127.0.0.1 -p 7777 127.0.0.1 21232

# server sends reply with the mapped sequence nr., correct sender
msg2="(msg 2: m1 server to client)"
msg2_expect="(msg 2: s1 server to client)"
echo "$msg2" | nc --send-only -u -s 127.0.0.1 -p 2123 127.0.0.1 21232

sleep .1
kill %1 %2 %3

# log what has reached the server and client ends, matched against
# gtphub_nc_test.ok
retval=0
echo "--- recv_server:"
cat recv_server
if [ "$(cat recv_server)" == "$msg1_expect" ]; then
	echo "OK"
else
	echo "*** FAILURE"
	retval=1
fi

echo "--- recv_client:"
cat recv_client
if [ "$(cat recv_client)" == "$msg2_expect" ]; then
	echo "OK"
else
	echo "*** FAILURE"
	retval=2
fi

echo "done"
exit "$retval"
