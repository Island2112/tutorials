#!/bin/bash

export brohost="192.168.1.202"

export maindir="/home/ilha/tests/ds3"
export baselinedir="$maindir/baseline" 
export kerneldir="$maindir/kernel" 
export offloadeddir="$maindir/offloaded" 

export originaltrace="ds3-canada-original.pcap"
export prefilteredtrace="ds3-canada-prefiltered.pcap"

export filter="((udp and port 137) or (udp and port 5355) or (udp and port 53) or (udp and port 5353) or (tcp and port 53))"

export loop="--loop=10"
export speedup="--multiplier=15"  
export tcpreplayparams="$loop $speedup"

function run_test {

	export broinittime="5s"
	export tcpreplaytime="180s"

	for i in {0..9}
	do
		ssh root@$brohost "cd $workdir ; \
				   mkdir -p $i ; \
				   cd $i ; \
				   rm -f *.log ; \
				   nohup $brocmd </dev/null >nohup_bro.log  2>&1 & "
		sleep $broinittime
		ssh root@$brohost "cd $workdir ; \
				   cd $i ; \
                        	   nohup sar 5 -u -n DEV -o sar.log </dev/null >>nohup_sar.log  2>&1 & "
		tcpreplay -q --stats=5 $tcpreplayparams -i enp0s8 $trace 2>&1 &
		sleep $tcpreplaytime
		killall -TERM tcpreplay
		ssh root@$brohost "killall -TERM bro sar"
	done

}

set -xe

ssh root@$brohost "mkdir -p $maindir $baselinedir $kerneldir $offloadeddir" 
#tcpdump -r $originaltrace -w $prefilteredtrace $filter

# Baseline Test
export trace="$originaltrace"
export workdir="$baselinedir"
export brocmd="bro -b -i enp0s8 /home/ilha/tests/mypolicy.bro"
run_test

# Kernel Test
export trace="$originaltrace"
export workdir="$kerneldir"
export brocmd="bro -b -i enp0s8 -f \"$filter\" /home/ilha/tests/mypolicy.bro"
run_test

# Prefiltered Test 

export trace="$prefilteredtrace"
export workdir="$offloadeddir"
export brocmd="bro -b -i enp0s8 /home/ilha/tests/mypolicy.bro"
run_test

