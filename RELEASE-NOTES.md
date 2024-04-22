RELEASE NOTES
=============

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
