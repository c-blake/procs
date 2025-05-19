#!/bin/sh
: "${j:=$(ncpu /2)}"
: "${t:=/dev/shm}"; export t
: "${prog:=s / r /stat r /cmdline R /exe r /io r /schedstat r /smaps_rollup}"
export PARC_PATHS="sys/kernel/pid_max uptime" prog
cd /proc; set [1-9]*    # Just to count procs to divide by j
echo $* | xargs --process-slot-var=J -n "$((1+$#/j))" -P "$j" \
 /bin/sh -c 'exec>>$t/p.$J;[ $J -eq 0 ]||unset PARC_PATHS;exec parc $prog $*' d0
cat $t/p.* >${PFA:-$t/pfs}
rm -f $t/p.*
