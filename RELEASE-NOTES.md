RELEASE NOTES
=============

Version: 0.8.12
---------------
  - Add a more precise load average "mvrn" with user-tunable decay to scrollsy.
    Use in default format (with what it averages, "prn").  Also colorize "prn"
    the same way as various load averages.

  - Add total interrupt jiffies (irj = hw + software) & use in default format.

  - Add "other jiffies" totalling the above with nice + steal to have a 4-field
    accounting of non-idle time.

Version: 0.8.11
---------------
  - Propagate runnable|stopped trait to the whole group under merge.

Version: 0.8.10
---------------
  - Just bump to get new cligen.

Version: 0.8.9
--------------
  - Add more short alias possibilities (active only if ../bin/procs is ln -s'd),
    namely verb-noun order equivalents for pd, pk, pf, pw: dp, kp, fp, wp & a
    very short 1-char `k` for `procs find -akill` since in the context of nixing
    a rogue process ASAP, getting keystrokes through an X server/terminal/shell
    is often slower than run-time of `procs find` (i.e. the bottleneck).

  - Add ability to visually indicate sort order via `-g,--glyph` in both initial
    display and follow-on differential display (which has an independent sort).
    `--glyph` is `:`-separated.  If given 4 not 2 fields, last 2 are only for
    delay-differential mode and can be "", e.g. `-g+:-::` will suppress them.

  - Add ability to visually indicate a column is used for sorting `color order`
    just like `color delta` before it.

  - Old color = delta mode could (if header narrower than data, like RSS) add
    whitespace inside the header.  Fixed for both that & new color=order mode.

Version: 0.8.8
--------------
  - Default parc/$j to -1 & update help strings a bit

  - Fix configs/cb0 example configs

  - Make headers have same alignment as their data.  This particularly impacts
    PID which will now be right padded/flush-left (since first data column is),
    but may also impact any user `--hdrs`.  This is useful both as a redundant
    alignment cue and for any textual post-processing where lexing columns may
    otherwise get confused/need to handle more (literal) edge cases.

Version: 0.8.7
--------------

  - The example cb0/ config family are all updated.  If you "just copy them"
    as per install instructions, you might want to copy over them in you $HOME,
    but you really should `diff` first to see what changes you may have made.

  - Always merge in oldest-\>newest start-time order for determinism.  Merges
    keep the older|lesser pid/ppid/pidPath type identifiers.

  - Do not try to read `smaps_rollup` for kthreads which always fails & do not
    auto-fail on `psIO` files (which may also need root).

  - Convert %D to "" format if first sort key is not also D to not misleadingly
    indent the sorted table.

  - Add %/ format code for pidPath to better self-explain -oD sort modes

  - Add `-e, --eqLeaf`: to equalize leaf processes (those sans kids) to make
    n-level sorting w/the `-oD` prefix needed for a "forest look" more useful
    (instead of comparison always terminating at the unique-by-definition PID).

    Combined with prior new format code, `pd -sb -eoDJ -f^='%/ '` shows things
    sorted first into the kthread/init pair, then kidless but internally ordered
    by cumulCPU time, then each kid of init with its last level kids also all
    time-sorted.  Meanwhile, `-eoDT` instead does maybe-nicer start-time order.

  - Fix bug of %e always formatting to zero.  Works w/both -t=on/off now.  You
    want to add schedSt=true to your config (or -t locally just to formats you
    care about) when speed matters less than CPU time accounting precision and
    you are sure your kernel provides PID/schedstat.

  - Add `util/parc.nim` which ONLY does /proc data collection into cpio, e.g.
    `cd /proc; parc s / r /stat R /exe [1-9]* >p.cpio`.  While this was mostly
    motivated by rather surprising in-kernel slowness of `/smaps_rollup` for a
    more nicely rolling up PSS field, there may be other slow files and there
    may also be thousands of processes/threads.

    GNU cpio, bsdcpio from libarchive, and paxcpio all seem to find produced
    archives acceptable.  I chose the "obsolete bin" format for max simplicity
    and efficiency (no binary-\>ASCII-\>binary) writing/parsing.  Its < 64KiNode
    limits may induce change, but then again /proc also has no hard-links, so
    maybe not.  You can unpack as root (needed for file owner diversity) in
    /dev/shm and re-pack however.  You can also always convert without unpack
    via libarchive's examples/tarfilter.c or similar.

  - Add to procs find/pf/pk `-H, --ifHandled` (or `--if-handled`, if you prefer)
    to mimic similar functionality recently added to `pkill`.

  - Add `-R, --RunState` (or `--run-state`, if you prefer) for filtering based
    on the 1-letter run-state code from /proc/PID/stat.

  - Move `kill`-> `pidfd_open` & `pidfd_send_signal` in `procs find`.  Linux in
    2019 (&glibc 2022) began full support of pidfd interfaces.  As of 2025, MUSL
    still doesn't seem to; Unsure of plans, but TLDR - I've waited long enough.

    Some background: This limits PID recycling/wraparound races to the time from
    getdents(/proc) to the loop iteration classifying a PID.  USUALLY, this is a
    tiny fraction of 20 ms..8 sec to wrap process tables under fork load UNLESS:
    A) `pid_max` is very small, B) effective `pid_max` is very small (e.g. a
    zillion sleeps, only partially mitigated by ulimit -u per-uid), C) per-PID
    loop work is very costly (e..g expensive regular expressions|/proc queries),
    or D) per-PID work is effectively very costly by an unfortunate SIGSTOP/etc.
    { As with any race, these "very"s are all about relative scales & I may well
    have missed some! } { 20 ms is for pid_max=1e4; 8 sec, extrapolated 4e6. }

    Due to its good loop design, this was *always* the race for simple uses of
    `procs find -akill`.  The new method mostly helps actions use stable process
    Ids for delayed `SIGTERM` -> `SIGKILL` style signalling protocols and the
    `wait` & `Wait` for unrelated-to-target-process waiting where delays can be
    large on purpose.  Things needing full table scans before acting (`--newest`
    & `--oldest`) also benefit some.

    6 years later & Linux still has no API analogues for pid-taking stuff other
    than signaling (eg. anything in `man 7 sched`) but for madvise.  Presumably,
    the assumption is that misidentified targets of such calls do limited damage
    (though superusery CAP_SYS_NICE guards most such calls under *exactly the
    OPPOSITE* assumption!).  Also, `process_madvise` has no *vanilla* pid API.

Version: 0.8.6
--------------
  - `pf` was unable to save "/proc/meminfo" in a cpio archive.  Add & document
    the new `meminfo` FileSrc type.  So, now a better sample invocation is:
    `PFA=/tmp/my pf -fF,=,dst,stat,exe,io,sched,status,mem -A1 -ac .`

  - Add missing sort-by-label 'l' key

  - `pf` fixed to not read --ns unless given needed (was reading /proc/0).

  - Fix behavior on files missing from archives to match un-openable /proc items

  - Clean up `proc cpioLoad` using a new `cligen/mslice` API.  (Needs a new
    cligen release).

  - New procs display --na=string option for users to adjust how missing values
    (or Not Available or N/A or --na) are represented.

  - Add "%" value coloring (m/e/E formats) similarly to old system load colors.
    Update example config cb0.  People liking smooth (but also less "nameable")
    color schemes should look at:
        https://github.com/c-blake/bu/blob/main/doc/dfr.md#configuration
    { but note that besides "w" (for wvLen) scale used there, `pd --version`
      tells you others (e.g., right now: viridis hue[,s,v] gray pm3d). }

  - m/%MEM was the raw fraction not a percentage.

  - m/e/E use a new concept in condensed float formatting I call `nearUnity4`
    which basically means whichever of 0 De-N .DDD D.DD DD.D DDDD DDeN DeNN inf
    seems appropriate for the range of the float - no K/M/G/T involved.  This
    can be fruitfully combined with replacing ppbT and %-color scales for nicer
    columns of this type.

  - vsize & rss are now max-accumulated in roll-ups; (PSS would "+=" nicely, but
    kernel doesn't maintain it incrementally => /proc//smaps emission is slow.)

Version: 0.8.5
--------------
  - Given worrisome EACCESS errors for readlink(exe) for kernel threads, just
    write our own cpio archive.  Set `PFA=someFile` in context of any `procs`
    subcommand & feed "someFile" to `cpio -id` in some dir to unpack.  You will
    need to be root to create files with ownership replicating /proc.

  - Given that we make our own archive already, the root annoyance & performance
    considerations of re-scanning /proc, adapt code to run off one of our `cpio`
    archives if `$PFS` is such an archive (cannot be "cd'd into").  Missing data
    is NOT backfilled from the live /proc - this is to work the same as if you
    had a mirror file tree or to capture /proc dynamism.  A consequence, though,
    is that if you re-run w/different subcommand/diff formats/sort orders or any
    other perturbation on needed data, that data will just be missing.

  - Given the above and the likelihood that a `pf` might precede a `pd` in some
    kind of external typing situation or just generally otherwise, provide a way
    for `pf` to populate a cpio archive with any per-pid processed sources.
    (Could be extended to system-wide `scrollsy` sources, on request/demand.)

    For example, `PFA=/tmp/my pf -fF,=,dst,stat,exe,io,sched,status -A1 -ac .`
    will populate the cpio archive `/tmp/my` with most basic per-PID data (but
    you should only read/save what you actually want).

    As with any other cligen utility, `pf -F ''` gives a list of all sources,
    named almost exactly after direntries in /proc/PID/.  This is kind of an
    optimizer/expert mode and so users need to "just know" what data lives in
    what per-PID files, but the alternative is knowing the 170 fields procs can
    currently parse which seems even harder.

  - Rename --schedStat -> --schedSt and document it & make it work in off/false
    mode as well as on/true mode.  Compare with cb0 configs `pd -su -t=off` to
    see if this is something that concerns you.

  - A new set of example config files (along with a `zsh` shell function & `awk`
    helper script) have been merged into `configs/kaminsky0`.  [The README.md
    there](configs/kaminsky0/README.md) elaborates and has screenshots.  A very
    high-level description might be "This may be a better starting point if you
    have a big server or fancy desktop Linux distro with a much more diverse
    process zoo you'd like to create more organized reports for." @mkaminsky
    contributed these (& actually made the original 2019 inspiring comment that
    led to the entire `procs.nim` program).

Version: 0.8.4
--------------
  - Add batch labeling to `procs.find`/`pf` via `--Labels=` which correspond,
    in-order to listed `PCREpatterns`.  Eg., `pf -Lzs -Lpf -Lab zsh fix foo ba`
    gives me: `zs_0:705 zs_1:707 zs_2:710 zs_3:713 pf:None huh:None`

  - Allow users to re-direct `/proc` inquiries to `$PFS`.  This helps debug &|
    analyze performance of snapshots &| use non-standard mount points.  E.g.:
```sh
rm -rf /dev/shm/proc; cp -a --parents /proc/[0-9]*/(stat|cmdline|exe) \
       /proc/sys/kernel/pid_max /proc/uptime /dev/shm
PFS=/dev/shm/proc pd whatever
```
    At least when I tried, both `tar` and `cpio` failed, but all utilities work
    on the ordinary files created by the `cp`.  `proc scroll` needs top-level
    /meminfo /stat /net/dev /diskstats /loadavg entries.  Which per-PID dirs &|
    files you need depends upon your pf flags/pd --format and you will need to
    be root if you want root/other-UID preservations.

    NOTE: procs may move to an optionally hash-indexed tar-ball as a /proc cache
    and interchange format.  If so it may make sense to interpret a $PFS ending
    in ".tar" as a single file, not a directory, and making it (with whatever
    files were needed) may be as simple as running `PFS=some/where/foo.tar pd`.

  - Make `bench.sh` more portable

Version: 0.8.3
--------------
  - In the last release `pcr_X` would truncate formatted strings to 256 to match
    against the regexes.  This release enlarges that to 2048 (~25 rows on an 80
    column terminal!).  Some limit seems prudent since command-lines can be much
    longer than this (e.g. `**.c`), yet proc types seem (to me) unlikely to be
    distinguished beyond a "small" prefix.  We can enlarge a bit more or if no
    modest limit works for everyone add a CLI option to be user set.)

  - Single-\>multi-char labels with ':' delimiter in labA:labB:PID on input & in
    output LABELS field.  Field width here is a generous 30 so users can say,
    e.g.  `pd -W$((COLUMNS+30) -f '%l..' ...| tslice:30` to get nice text tables
    without losing any important external typing information.

Version: 0.8.2
--------------
  Reconceive `pcr0`/`pcrF` feature of version 0.8.0 more generally.  Now the
  syntax `pcr_?` means "apply the perl-compatible regexes" to the "wide version"
  formatted output of any of basic format code `?` (from procs display help
  table, like 'c' or 'C' or etc.).  The old "bare `pcr`" remains as a backward
  compatible shorthand for `pcr_c`.  `pcr_C` replaces weeks old `pcrF` and
  `pcr0` is retired (one can probably do a good enough regex with a '^' anchor
  in `pcr_C` to handle it, anyway).

  Add 2 new codes:

    - '@' for the `/proc/*/exe` symlink which may be the most reliable way to
      group some process families but needs permissions (ie., normal user cannot
      `readlink` root-owned `/proc/*/exe`).

    - 'l' that emits newly "passed through" prefixes given by the user on the
      command-line.  Together with the newly ignore prefixes to pids, this
      allows "fully external" proc classifying to be "imported" into the procs
      "type system" for display by `pcr_l` matching whatever label/tag you gave
      the process by your external algorithm.  This import can be useful for
      either colorization or merges/roll-ups, as per usual typology here.

  Add a simple `bench.sh` script showing both relevant results for this design &
  another eg. of [bu/tim.md](https://github.com/c-blake/bu/blob/main/doc/tim.md)
  delivering time measurements with low single digit microsecond errors (which
  reproduce within error bars for me, re-running bench.sh on the same machine).
  { Of course, when `pk` (aka `procs find -ak`) speed matters most, "scheduler
  time dilation" can stretch milliseconds out to seconds and beyond.  So, this
  has actually made a real difference in my life with, e.g. rogue `nimsuggest`
  instances trying to use all RAM past the point of swapping and so on. }

Version: 0.8.1
--------------
  Add `procs find --otrTerm` (aka `pf -O`) to terminate PID lists.

  Use `delim` & `otrTerm` more consistently so that output is better framed /
  separable even without labeling. This is ~BREAKING.  E.g. `/proc/$(pf foo)/X`
  now gets a space breaking the path, since `pf` does know how many PIDs will be
  printed in advance.  However, special cases like `--first|--oldest|--newest`
  turn `delim` to `""` so `/proc/$(pf -o foo)/X` works as before.  Further, as
  before in Zsh, this still works: `ls -ld /proc/$(pf -d\| zsh)/cwd`.

Version: 0.8.0
--------------
  Big bug fix for `procs find` aka `pf` where a reused object had stale data.
  At the library level, add & export `Proc.clear` if others want to use this.

  Use `/proc/sys/kernel/pid_max` to tell how many decimals PIDs can be & yield
  more reliable "tabular shape" across Linux setups.

  Add `pcr0` & `pcrF` kind match operators to match against either $argv[0] or
  the fully joined $argv for purposes of user-defined roll-ups.

  Explicit lists of PIDs with duplicates no longer duplicate output rows.

  New %A = AncestorID format specifier.

  Two new actions for `pf` to help restrict the report:
    - path { parent(parent(...())) reversed } for more focused ancestry.
    - aid for ancestor id / whole family tree selection
  An e.g. of the first - report on the PPID(PPID(..)) "path" of any proc whose
  (command) contains "nvim": `pd -sb $(pf -ap '\bnvim\b')`. A more involved
  wrapper of the second, assuming style `A*` begins with the new %A, reports
  whole family trees for all commands with the grep pattern in $1:
```sh
# NOTE: \\bPAT will NOT match itself; E.g. puf \\bsh
: "${pf=-f}"                    # E.g.s: `pf=`, `pf="-f -x$$"`
: "${g:=grep --color=always}"   # grep with any extra flags
: "${d:=`wc -c </proc/sys/kernel/pid_max`}" # PID digs + 1colSep space
COLUMNS=$((COLUMNS+d)) pd -sA | # Assume style A* starts with %A
  $g '^\(^[\[[0-9;]*m\)*\<\('$(pf -aa -d'\|' $pf $1)AID'\)\>\|'"$1" |
  tslice $d:                    # New `bu/tslice` utility
```

Version: 0.7.3 & 0.7.4
--------------
    Just pretty minor/dumb edits & .nimble dependency updates

Version: 0.7.2
--------------
    Fix `schedStat` spelling (hitherto undetected since `styleCheck=usages styleCheck=error` does not work unless `hint[Name]=on` is also set).

    Add option to preface each sample in differential-delay mode with time.

    Add a built-in type "self" for the procs display process itself.
    This can be nice either to suppress it, say in
        `procs display --delay=0.001 --excl=self`
    or to emphasize it (e.g. to know which tty ran program in tree formats) with
    special colorization.

    Update example color config, correctly renumbering side-comment slots and
    default to struck (& probably bold, unlike zombies).

Version: 0.7.1
--------------
    Add one flavor of mUsed for `scrollsy` - total-complement to mAvl.

    Right align headers for right aligned fields

    Rename NI -> NICE; F -> FLAGS; Abbreviation unhelpful

    TTY -> TT & 2-column format to save a terminal column in the common case.

Version: 0.7.0
--------------
    Add new parts per billion CPU time usage as %b; Update
    configs/cb0/style.auser to use it.

    Give 2 new ways to test for existence of any matches:
      - `pf -e STUFF || start-it`
      - `pf -ac STUFF >/dev/null || start-it`

    Bump minor since this adds an important new use case (though, arguably, so
    did nanosecond time stamps).

    Fix bug converting delay TimeSpec from seconds to jiffies

    Fix longstanding environ 'e' masks %cPU 'e' bug

Version: 0.6.5
--------------
    Rely upon `cligen/puSig` for posix/unix signal names.

Version: 0.6.4
--------------
    Add PSS (proportional set size) keyed by 'M' / "%M".

    Handle formatting negative numbers better (for differential mode).

Version: 0.6.3
--------------
    Add nanosecond time stamp field for high-resolution logs

    Add --blanks for differential report readability (esp. w/no header row..)

Version: 0.6.2
--------------
    Just for cligen dependency version bump.

Version: 0.6.1
--------------
    silence some `mm:arc` performance warnings.

Version: 0.6.0
--------------
    Update default distributed style to have %a (age) as well as used %Jiffies.

    Work around long-present crash in differential mode if compiled in mm:arc
    mode via `template forPid`.
    
    Speed up `procs find` by 1.25x via cligen/mslice number parsers.

    Add some real installer-script logic to procs.nimble.

Version: 0.5.8
--------------
    Better help.  Add text attr help dump to version text.
    Improve default distributed configs.

Version: 0.5.7
--------------
    Fix bad bug in newest/oldest

Version: 0.5.5..6
-----------------
    Add `--age` to `pf`; Make --actions take -a name; `--age` take `-A`.

Version: 0.5.4
--------------
    Add --limit feature to time out existence checks in wait* actions.

Version: 0.5.2..3
-----------------
    Just dep/nimble futzing.

Version: 0.5.1
--------------
    Clean-compile/de-warnification & do pty not tty in `ttyToDev`.

Version: 0.5.0
--------------

    Nicer Control-C exits

    Emphasize the 'v' in requested "invert" `procs find`/`pf` feature.

    Extend find/act/kill self-avoidance to own whole process group.

    Make back/forward compatible with nimPreviewSlimSystem

Version: 0.4.1
--------------

    Quieter exit upon Control-C in all subprograms.  (This could arguably be
    a cligen feature adjustable by end CLusers, like SIGPIPE behavior.)

    Extend -xPPID self killing/acting-avoidance to include own process group.

Version: 0.4
------------

    Add -i flag to `pf` to force pattern insensitivity { (?i) added to start of
    every pattern as per lib/impure/nre.nim documentation. Seems to work fine. }

    Make `pw` less chatty (only ^C not default Nim message), but still
    exit 130 in case there is some `pw patterns &&` shell construct.

    For example config, add vbox & make Style delta(D) option order same as
    order(o) { although this is just for visual consistency since any delta
    produces a report with some `-d1` mode }.  Also combine first 4 eth devs.
    Modernize darkBG & lightBG theme examples.

    For >=100% just show integer percentage; 3 significant figures is plenty.

    Ensure data is flushed to stdout before sleeping in differential mode.

    Do not total syscall IO & blockdev IO for %<,%> (too often doubles IO).

    Make build clean under `--styleCheck:hint --styleCheck:usages`.  Also get
    rid of cstring warnings.  Fix several deprecations; mv `Table.add` ->
    `Table.[]=` ; While technically [ug]id -> user name mapping is multivalued
    we were only using a random one of the many values.  Now the last writer
    wins.  Maybe 1st writer should, but user/group name aliases are rare.
    Adapt to https://github.com/nim-lang/Nim/pull/17402

Version: 0.3
------------
    Use textAttrOff, not literal.

    Make wchan 2 more terminal columns + __x86_sys_ prefix strip really enhances
    readability of truncated System.map symbols.

    Include RSS as well as rest of /proc/PID/(status|statm) in `minusEq` for
    differential mode with `basic` style.

    Work around a weird memory overallocation bug.

Version: 0.2
------------
  Get EUID working correctly (basically fstat on /proc/PID/ directory is
  reliable while entries under /proc/PID/ are not).

  Now compiles and seems to work with --gc:arc (I could not break it, anyway).

  On my machine, compiled with gcc-10-PGO and `--gc:arc`, Nim `pd -d 0.00001`
  is now 775 samples per second compared to the C `top -ib -d0` 725/s.  I.e.
  Nim is 1.07x faster than C tuned for decades by performance sensitive `top`
  watchers.  It is true that `top -b -d0` lseek()s & re-parses a few system-
  wide files every sample (/proc/loadavg, /proc/stat, /proc/uptime), this is
  in addition to literally 320 /proc/PID files and so unlikely to fully explain
  the difference.  I suspect the way top is reading /var/run/utmp very, very
  carefully with several times over reset alarm(2) calls.  Regardless, it's
  probably fair to say performance parity with C is basically achieved now.

  `gc:arc` remains rough, though.  Besides
    https://github.com/nim-lang/Nim/issues/13269 and
    https://github.com/nim-lang/Nim/issues/13322, I also had to make these
  commits to workaround what I think are independent other `gc:arc` bugs:
    https://github.com/c-blake/procs/commit/7a0318f62143ef9334fd676cf6523b46587a2ebf
    https://github.com/c-blake/procs/commit/dfcbf74939a3210c6a42a8b79a2f68df7b59a735
  I tried to reduce those latter two bugs to small reproducibles but it was not
  easy enough.  So, I just worked around them instead.

  Add parsers for /proc/loadavg, /proc/stat, /proc/diskstats, /proc/net/dev and
  a new command-line subcommand `scrollsy`.  This is still a work very much in
  progress (needs at least parameterization for which disk/net iface/CPU).

Version: 0.1
------------
  Initial public release
