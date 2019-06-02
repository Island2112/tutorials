root@labzeek:/usr/share/bro/base/frameworks/packet-filter# vim main.bro

cp /usr/share/bro/base/init-default.bro /home/ilha/tests/mypolicy.bro

bro -b -i enp0s8 mypolicy.bro

bro     ((udp and port 137) or (udp and port 5355) or (udp and port 53)) or (udp and port 5353) or (tcp and port 53))

Remember to run clearips.sh.
After the tests, use parselogs.sh.


