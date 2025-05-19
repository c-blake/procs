#!/bin/sh
set -e
[ -t 1 ] && { echo 1>&2 "Usage: parc.sh > /some/where/foo.cpio"; exit 1; }
: "${j:=$(nproc)}"
: "${prog:=s / r /stat r /cmdline R /exe r /io r /schedstat r /smaps_rollup}"
export t="/dev/shm"     # Meant as a starting point; mktemp -d, trap etc
# Eg. github.com/c-blake/bu/blob/main/doc/funnel.md#example-xargs-wrapper-script
export PARC_PATHS="sys/kernel/pid_max uptime" prog
cd /proc || exit 2
set [1-9]*              # Just to count procs to divide by j
echo $* | xargs --process-slot-var=J -n "$((1+$#/j))" -P "$j" \
 /bin/sh -c 'exec>>$t/p.$J;[ $J -eq 0 ]||unset PARC_PATHS;exec parc $prog $*' d0
cat "$t/p".*
rm -f "$t/p".*
