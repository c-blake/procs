#!/bin/sh
: "${r=chrt 99 taskset -c 2}" # r= bench.sh works else need root2shrink meas.err
[ -r "$HOME/.config/nimble/nimble.ini" ] &&
   . "$HOME/.config/nimble/nimble.ini" # MUST USE A="B" SYNTAX TO ASSIGN
: "${u=$HOME/bin:${nimbleDir-$HOME/.nimble}/bin}"
: "${e=env -i HOME=$HOME CLIGEN=/n PATH=/usr/local/bin:/usr/bin:$u}"
: "${t=-k2 -o14 -n14 -m14 -uμs}" # These yield ~0.2..0.3% errors for me
N="/dev/null"                 # This uses both bu/tails and bu/tim
echo $(find /proc -maxdepth 1 -name '[1-9]*' -type d|tails -h1 -t1 -C1 -d '') |
 (read n first last
  p=$(sed -e's/).*//' -e's/.*(//' < "$first/stat")
  printf "first/proc/*/stat-Pattern: \"%s\"\n" "$p"
  echo "Roughly $((n - 4)) processes adjusting for (find, tails, 2 shells)"
  $r $e tim $t "pf -e1 '$p'" "pf -e1 xyzPDQnoSuchCommand||:" "pgrep -x init>$N")

# i7-6700k (no HT,4.7GHz)
# first/proc/*/stat-Pattern: "init"
# Roughly 196 processes adjusting for (find, tails, 2 shells)
# 201.76 +- 0.62 μs       (AlreadySubtracted)Overhead
# 1014.1 +- 2.2 μs        pf -e1 'init'
# 2060.1 +- 6.5 μs        pf -e1 xyzPDQnoSuchCommand||:
# 7724 +- 16 μs           pgrep -x init>/dev/null
#
# i7-1370P
# first/proc/*/stat-Pattern: "init"
# Roughly 323 processes adjusting for (find, tails, 2 shells)
# 92.54 +- 0.73 μs        (AlreadySubtracted)Overhead
# 582.7 +- 2.8 μs         pf -e1 'init'
# 1345.7 +- 4.2 μs        pf -e1 xyzPDQnoSuchCommand||:
# 5539.6 +- 6.3 μs        pgrep -x init>/dev/null
#
# "Up to" 7.617 +- 0.023 times faster on one system; 9.507 +- 0.047 on another.
# $ a ((2060.1 +- 6.5)-(1014.1 +- 2.2))/196 -> 5.337 +- 0.035 μs/process
# $ a ((1345.7 +- 4.2)-(582.7 +- 2.8))/323 -> 2.362 +- 0.016 μs/process
#
# # Why This Can Matter:
# On some 96 core/192 thread beast with 192/4=48*200 processes, you may see more
# like 48*7.7ms=370ms times which may well be human noticeable on fully unloaded
# systems. A common `pf -ak` use case for me is to nix rogue processes hammering
# systems, in which case .37 sec can easily be multiplied out to many seconds or
# even multiple minutes.  Since the point of sending a signal is to "fix" system
# responsiveness, doing so with unneeded slowness adds salt to the wound.
