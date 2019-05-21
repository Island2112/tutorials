#!/usr/bin/env python2

# Loosely based on http://csie.nqu.edu.tw/smallko/sdn/p4-clone.htm

import os

os.system('/usr/local/bin/simple_switch_CLI --thrift-port 9092 < s3-cli.txt')
os.system('/usr/local/bin/simple_switch_CLI --thrift-port 9091 < s2-cli.txt')
os.system('/usr/local/bin/simple_switch_CLI --thrift-port 9090 < s1-cli.txt')

