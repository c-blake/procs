#!/bin/zsh -f
set -e
[ -t 1 ] &&{ echo 1>&2 "Usage: parc.zsh > /dev/shm/\$LOGNAME-pfs.cpio"; exit 1;}
: "${j:=$(nproc)}"      # j jobs parallel /proc files data collector
t="/dev/shm"            # Meant as a starting point; mktemp -d, trap etc
# Eg. github.com/c-blake/bu/blob/main/doc/funnel.md#example-xargs-wrapper-script
cd "/proc" || exit 2    # proc-fs root
pids=([1-9]*)           # All processes *right now*; Inherently racy
n=${#pids}              # Number total
m=$(( (n + j - 1)/j ))  # Batch size
for ((i=1; i<=j; i++)); do # Fire $j batches
    slice=(${(@)pids[$(( (i-1)*m + 1 )),$((i*m <= n ? i*m : n))]})
# `procs display` style drives specific list needed here.  To show MyStyle needs
# `PFA=/tmp/x pd -sMyStyle; cpio -tv</tmp/x|tail`, but NOTE unreadable entries
# (eg. kthread /exe, otherUser /smaps_rollup) are dropped from the cpio archive.
    [[ $i = 1 ]] && export PARC_PATHS="sys/kernel/pid_max uptime meminfo"
    parc s /   r /stat      r /cmdline      R /exe \
         r /io r /schedstat r /smaps_rollup $slice > $t/pfs.$$.$i &
    unset PARC_PATHS
done
wait                    # Wait for last to finish
cat "$t/pfs.$$".*       # Merge results
rm -f "$t/pfs.$$".*     # Clean-up temporary files
