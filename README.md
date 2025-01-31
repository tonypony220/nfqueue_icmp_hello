# nfqueue_icmp_hello
dummy util to test error codes which would handle redirected icmp packets from nfqueue

requirements
`apt install  libnetfilter-queue-dev`

redirect icmp packets 
`iptables -A INPUT -p icmp --icmp-type echo-request -j NFQUEUE --queue-num 0`

