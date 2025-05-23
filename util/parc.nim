const Use="""Programmed ARChiver; Like cpio -oHbin, but works on odd /proc files
Usage:
  d=DIR(/proc) j=JOBS(1) parco GLOBALS -- PROGRAM [-- ROOTS]
where DIR is the directory to run out of (must be cd-able), JOBS refers to
process parallelism like make -j, GLOBALS are $d-relative paths to archive,
PROGRAM is a series of archival steps to make against ROOTS.  If ROOTS are
omitted, every top-level direntry of $d matching [1-9]* is used.  Program
steps are LETTER/entry where LETTER codes are s:stat r:read R:ReadLink and
these actions are run with each ROOT as a prefix to \"/entry\".  E.g.:
  j=8 parc sys/kernel/pid_max uptime meminfo -- s/ r/stat r/io R/exe \\
           r/cmdline r/schedstat r/smaps_rollup >/dev/shm/$LOGNAME-pfs.cpio
snapshots what `procs display` needs for most formats/sorts/merges. To see
needs for your specific case of style X, `PFA=y pd -sX; cpio -tv < y|less`,
but NOTE parc drops unreadable entries(eg. kthread /exe, otherUser /io) from
written cpio archives, which are then treated as empty files by `pd`."""

when not declared stderr: import std/syncio
import std/[posix, os, strutils], cligen/[posixUt, osUt]
var av = commandLineParams()

proc add(s: var string, t: cstring, nT: int) =  # Sort of like a C `memcat`
  let n0 = s.len
  s.setLen n0 + nT
  if s.len > 0: copyMem s[n0].addr, t, nT       # Both s and t could be ""

type Rec* {.packed.} = object       # Saved data header; cpio -oHbin compatible
  magic, dev, ino, mode, uid, gid, nlink, rdev: uint16 # magic=0o070707
  mtime : array[2, uint16]
  nmLen : uint16
  datLen: array[2, uint16]              #26B Hdr; Support readFile stat readlink

var rec = Rec(magic: 0o070707)          # Heavily re-used CPIO record header
var st: Stat
var buf: string
var Pad = '\0'; var pad0 = Pad.addr     # Just a 1 byte pad buffer for \0
let (o, e) = (stdout, stderr)           # Short aliases
proc clear(rec: var Rec) = zeroMem(rec.addr, rec.sizeof); rec.magic = 0o070707
proc odd[T: SomeInteger](n: T): int = int(n.int mod 2 != 0)

proc writeRecHdr(path: cstring; pLen, datLen: int) =
  let path = if path.isNil: nil else: cast[pointer](path)
  let pLen = if path.isNil: 0   else: pLen
  rec.nmLen     = uint16(pLen + 1)      # Include NUL terminator
  rec.datLen[0] = uint16(datLen shr 16)
  rec.datLen[1] = uint16(datLen and 0xFFFF)
  discard o.uriteBuffer(rec.addr, rec.sizeof)
  discard o.uriteBuffer(path    , pLen + 1)
  if pLen mod 2 == 0: discard o.uriteBuffer(pad0, 1)

proc fromStat(rec: var Rec; st: ptr Stat) =
  rec.dev      = uint16(st[].st_dev)    # Dev should neither change nor matter..
  rec.ino      = uint16(st[].st_ino)    #..so CAN fold into above for 4B inode.
  rec.mode     = uint16(st[].st_mode)
  rec.uid      = uint16(st[].st_uid)
  rec.gid      = uint16(st[].st_gid)
  rec.nlink    = uint16(st[].st_nlink)  # Generally 1|number of sub-dirs
  rec.rdev     = uint16(st[].st_rdev)   # Dev Specials are very rare
  rec.mtime[0] = uint16(st[].st_mtime.int shr 16)
  rec.mtime[1] = uint16(st[].st_mtime.int and 0xFFFF)

proc stat(a1: cstring, a2: var Stat): cint = # Starts "program" for PID subDirs
  proc strlen(s: pointer): int {.header: "string.h".}
  discard posix.stat(a1, a2) # rec.clear unneeded: stat sets EVERY field anyway
  rec.fromStat a2.addr; writeRecHdr a1, a1.strlen, 0; flushFile o

proc readFile(path: string, buf: var string, st: ptr Stat=nil, perRead=4096) =
  posixUt.readFile path, buf, st, perRead # Does an fstat ONLY IF `st` not Nil
  if buf.len > 0:                         # rec.clear either unneeded|unwanted
    if not st.isNil: rec.fromStat st      # Globals fstat field propagation
    else: rec.mode = 0o100444; rec.nlink = 1 # Regular file r--r--r--; Inherit..
    writeRecHdr path.cstring, path.len, buf.len #..rest from needed last stat.
    discard o.uriteBuffer(buf.cstring, buf.len)
    if buf.len mod 2 == 1: discard o.uriteBuffer(pad0, 1)
    flushFile o

proc readlink(path: string, err=e): string = # Must follow `s` "command"
  result = posixUt.readlink(path, err)  # rec.clear either unneeded|unwanted
  if result.len > 0:                    # Mark as SymLn;MUST BE KNOWN to be SLn
    rec.mode = 0o120777; rec.nlink = 1  # Inherit rest from needed last stat.
    writeRecHdr path.cstring, path.len, result.len + 1
    discard o.uriteBuffer(result.cstring, result.len + 1)
    if result.len mod 2 == 0: discard o.uriteBuffer(pad0, 1)
    flushFile o

var jobs=1; var soProg=1; var eoProg, i: int  # Globals to all parallel work
var thisUid: Uid                              # Const during execution, EXCEPT i
proc perPidWork(remainder: int) =
  template `+!`(p: cstring, i: int): cstring = cast[cstring](cast[int](p) +% i)
  var path: string
  while i < av.len:
    if i mod jobs != remainder: inc i; continue
    path = av[i]; let nI = path.len
    for j in soProg..<eoProg:           # Form "ROOT/entry" in `path`
      path.setLen nI; path.add av[j].cstring +! 1, av[j].len - 1
      if   av[j][0] == 's': discard stat(path.cstring, st)
      elif av[j][0] == 'r':
        if path == "/smaps_rollup":
          if thisUid == 0 or thisUid == st.st_uid: readFile path, buf
        else: readFile path, buf
      elif av[j][0] == 'R': discard readlink(path, nil)
    inc i

proc driveKids() =
  let quiet = existsEnv("q")
  var pipes = newSeq[array[0..1, cint]](jobs)
  var fds   = newSeq[TPollfd](jobs)
  for j in 0..<jobs:            # Re-try rather than exit on failures since..
    while pipe(pipes[j]) < 0:   #..often one queries /proc DUE TO overloads.
      if not quiet: e.write "parc: pipe(): errno: ",errno,"\n"
      discard usleep(10_000)    # Microsec; So, 10 ms|100/sec
    var kid: Pid
    while (kid = fork(); kid == -1):
      if not quiet: e.write "parc: fork(): errno: ",errno,"\n"
      discard usleep(10_000)    # Microsec; So, 10 ms|100/sec
    if kid == 0:                # In Kid
      discard pipes[j][0].close
      if dup2(pipes[j][1], 1) < 0: quit "parc: dup2 failure - bailing", 4
      discard pipes[j][1].close
      perPidWork j; quit 0      # write->[1]=stdout; Par reads from pipes[j][0]
    else:
      discard pipes[j][1].close
      fds[j] = TPollfd(fd: pipes[j][0], events: POLLIN)
  var buf = newSeq[char](4096)
  var nLive = jobs
  while nLive > 0:
    if poll(fds[0].addr, jobs.Tnfds, -1) <= 0:
      if errno == EINTR: continue
      quit "parc: poll(): errno: " & $errno, 5
    for j in 0..<jobs:
      template cp1 =    # Write already read header `rec` & then cp varLen data
        discard o.uriteBuffer(rec.addr, rec.sizeof)     # Send header to stdout
        let dLen = (rec.datLen[0].int shl 16) or rec.datLen[1].int
        let toDo = rec.nmLen.int + rec.nmLen.odd + dLen + dLen.odd # Calc size
        buf.setLen toDo                                 # Read all, blocking..
        while (let nR=read(fds[j].fd, buf[0].addr, toDo); nR<0): #..as needed.
          discard usleep(500) #; e.write "parc: had to wait\n"
        discard o.uriteBuffer(buf[0].addr, toDo)        # Send body to stdout
      if fds[j].fd != -1 and fds[j].revents != 0:
        if (fds[j].revents and POLLIN) != 0:                # Data is ready
          if (let nR = read(fds[j].fd, rec.addr, rec.sizeof); nR > 0): cp1
          else: (dec nLive; if close(fds[j].fd)==0: fds[j].fd = -1 else: quit 6)
        if (fds[j].revents and POLLHUP) != 0:               # Kid is done
          while (var nR = read(fds[j].fd, rec.addr, rec.sizeof); nR > 0): cp1
          dec nLive; if close(fds[j].fd)==0: fds[j].fd = -1 else: quit 7

proc addDirents() =     # readdir("."), appending $dir/[1-9]* to av[], ac
  let fd = open(".", 0o200000) # O_DIRECTORY
  var dts: seq[int8]
  let dents = getDents(fd, st, dts.addr, avgLen=10)
  for j, dent in dents:
    if dts[j] == DT_DIR and dent[0] in {'1'..'9'}: av.add dent
  discard fd.close
                        # # # MAIN LOGIC/CLI PARSE # # #
if av.len < 1 or av[0].len < 1 or av[0][0] == '-': quit Use, 1
let dir = getEnv("d", "/proc");
if chdir(dir.cstring) != 0: quit "cannot cd " & dir, 2
thisUid = getuid()
while i < av.len:
  if av[i] == "--": inc i; soProg = i; break
  if av[i].len > 0: readFile av[i], buf, st.addr
  inc i
if soProg >= av.len: soProg = av.len - 1
if av[soProg][0] != 's': e.write "parc: PROGRAM doesn't start w/\"s\"tat\n"
while i < av.len:
  if av[i] == "--": break
  if av[i].len < 2 or av[i][1] != '/' or av[i][0] notin {'s','r','R'}:
    quit "bad command \""&av[i]&"\" (not [srR]/XX)", 4
  inc i
eoProg = max(i, soProg)
if eoProg<=soProg: e.write "No PROGRAM; Start(",soProg,") >= End(",eoProg,")\n"
else:
  if i < av.len: inc i                # skip "--" for next for loop
  if i == av.len: addDirents()
  if (jobs = getEnv("j", "1").parseInt; jobs <= 0):
    jobs += sysconf(SC_NPROCESSORS_ONLN)
    if jobs < 0: jobs = 1
  if jobs == 1: perPidWork 0
  else: driveKids()
rec.clear; rec.nlink = 1; writeRecHdr cstring("TRAILER!!!"), 10, 0
