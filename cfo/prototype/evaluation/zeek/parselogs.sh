#!/bin/bash 

rm *.log

export n=2
export sedopt='-r "s/ +/\t/g"'

for j in baseline kernel offloaded; do 
	for i in {0..9}; do 
		sar -u -f $j/$i/sar.log 
	done | sed -r "s/ +/\t/g" >> xcpu.log 
	for i in {0..9}; do 
		sar -n DEV -f $j/$i/sar.log 
	done | sed -r "s/ +/\t/g" >> xnet.log
	for i in {0..9}; do 
		echo $j $i `grep "packets rec" < $j/$i/nohup_bro.log` 
	done | sed -r "s/ +/\t/g" >> xpackets.log
done
