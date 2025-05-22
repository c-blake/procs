when not declared stderr: import std/syncio
import std/[posix, os, strutils], cligen/[posixUt, osUt]
proc cstrlen(s: pointer): int {.importc: "strlen", header: "string.h".}

type Rec* {.packed.} = object       # Saved data header; cpio -oHbin compatible
  magic, dev, ino, mode, uid, gid, nlink, rdev: uint16 # magic=0o070707
  mtime : array[2, uint16]
  nmLen : uint16
  datLen: array[2, uint16]              #26B Hdr; Support readFile stat readlink

var rec = Rec(magic: 0o070707)          # Heavily re-used CPIO record header
var pad0: array[512, char]              # Just a big pad buffer of all \0
let (o, e) = (stdout, stderr)           # Short aliases
proc clear(rec: var Rec) = zeroMem(rec.addr, rec.sizeof); rec.magic = 0o070707

proc writeRecHdr(path: cstring; pLen, datLen: int) =
  let path = if path.isNil: nil else: cast[pointer](path)
  let pLen = if path.isNil: 0   else: pLen
  rec.nmLen     = uint16(pLen + 1)      # Include NUL terminator
  rec.datLen[0] = uint16(datLen shr 16)
  rec.datLen[1] = uint16(datLen and 0xFFFF)
  let bytes = rec.nmLen.int + int(rec.nmLen mod 2 != 0) +
              datLen        + int(datLen mod 2 != 0)
  if bytes < 2:                         # This should simply not be possible
    e.write "parc: SHORT WRITE: nameLen=",rec.nmLen," dataLen=",datLen,"\n"
  discard o.uriteBuffer(rec.addr, rec.sizeof)
  discard o.uriteBuffer(path    , pLen + 1)
  if pLen mod 2 == 0: discard o.uriteBuffer(pad0.addr, 1)

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
  discard posix.stat(a1, a2) # rec.clear unneeded: stat sets EVERY field anyway
  rec.fromStat a2.addr
  writeRecHdr a1, a1.cstrlen, 0; flushFile o

proc readFile(path: string, buf: var string, st: ptr Stat=nil, perRead=4096) =
  posixUt.readFile path, buf, st, perRead # Does an fstat ONLY IF `st` not Nil
  if buf.len > 0:                         # rec.clear either unneeded|unwanted
    if not st.isNil: rec.fromStat st      # Globals fstat field propagation
    else: rec.mode = 0o100444; rec.nlink = 1 # Regular file r--r--r--; Inherit..
    writeRecHdr path.cstring, path.len, buf.len #..rest from needed last stat.
    discard o.uriteBuffer(buf.cstring, buf.len)
    if buf.len mod 2 == 1: discard o.uriteBuffer(pad0.addr, 1)
    flushFile o

proc readlink(path: string, err=e): string = # Must follow `s` "command"
  result = posixUt.readlink(path, err)  # rec.clear either unneeded|unwanted
  if result.len > 0:            # Mark as SymLn;MUST BE KNOWN to be SymLn
    rec.mode = 0o120777; rec.nlink = 1  # Inherit rest from needed last stat.
    writeRecHdr path.cstring, path.len, result.len + 1
    discard o.uriteBuffer(result.cstring, result.len + 1)
    if result.len mod 2 == 0: discard o.uriteBuffer(pad0.addr, 1)
    flushFile o

proc add(s: var string, t: cstring, nT: int) =
  let n0 = s.len
  s.setLen n0 + nT
  copyMem s[n0].addr, t, nT

let argc {.importc: "cmdCount".}: cint        # On POSIX, not a lib; importc
let argv {.importc: "cmdLine".}: cstringArray #..is both simpler & faster.

const u = """/proc archiver like cpio -oHbin, but works on weird /proc files.
Usage:
  cd /proc
  j=4 PARC_PATHS='sys/kernel/pid_max uptime meminfo' parc s / r /stat R /exe \
   r /cmdline r /io r /schedstat r /smaps_rollup [1-9]* >/dev/shm/$USER-pfs.cpio

Here s* means stat, r* means read, R* means ReadLink, $j indicates parallelism,
and $PARC_PATHS is split-on-space for global(non-perPID) paths done first.

`PFA=x pd -sX; cpio -tv < x | less` shows global and per-PID needs of style X,
but NOTE unreadable entries (e.g. kthread /exe, otherUser /io) are dropped from
cpio archives, which are then treated as empty files by `pd`."""

var jobs = 1; var i, eoProg: int              # Globals to all parallel work
var thisUid: Uid                              # Const during execution, EXCEPT i
proc perPidWork(remainder: int) =
  var i = i                                   #..And `i` gets a private copy.
  var st: Stat
  var buf, path: string
  while i < argc:
    if i mod jobs != remainder: inc i; continue
    if argv[i][0] notin {'1'..'9'}:
      e.write "parc warning: \"", $argv[i], "\" cannot be a PID\n"
    path.setLen 0; let nI = cstrlen(argv[i]); path.add argv[i], nI
    for j in countup(1, eoProg - 1, 2):
      path.setLen nI; let nJ = cstrlen(argv[j + 1]); path.add argv[j + 1], nJ
      if   argv[j][0] == 's': discard stat(path.cstring, st)
      elif argv[j][0] == 'r':
        if path == "/smaps_rollup":
          if thisUid == 0 or thisUid == st.st_uid: readFile path, buf
        else: readFile path, buf
      elif argv[j][0] == 'R': discard readlink(path, nil)
    inc i

proc driveKids() =
  let quiet = getEnv("parc_quiet", "").len >= 3
  var pipes = newSeq[array[0..1, cint]](jobs)
  var fds   = newSeq[TPollfd](jobs)
  for j in 0..<jobs:            # Re-try rather than exit on failures since..
    while pipe(pipes[j]) < 0:   #..often one queries /proc DUE TO overloads.
      if not quiet: e.write "parc: pipe(): errno: ",errno,"\n"
      discard usleep(20_000)    # Microsec; So, 20 ms|50/sec
    var kid: Pid
    while (kid = fork(); kid == -1):
      if not quiet: e.write "parc: fork(): errno: ",errno,"\n"
      discard usleep(20_000)    # Microsec; So, 20 ms|50/sec
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
        if nR != rec.sizeof: e.write "parc: SHORT PIPE READ: ",nR," BYTES\n"
        let dLen = (rec.datLen[0].int shl 16) or rec.datLen[1].int
        let bytes = rec.nmLen.int + int(rec.nmLen mod 2 != 0) +
                    dLen + int(dLen mod 2 != 0)         # Calculate size
        if bytes < 2:
          e.write "parc: SHORT RECORD: nameLen=",rec.nmLen," dataLen=",dLen,"\n"
          discard usleep(1)
        discard o.uriteBuffer(rec.addr, rec.sizeof)     # Send header to stdout
        buf.setLen bytes                                # Read all, blocking..
        while (let nR=read(fds[j].fd, buf[0].addr, bytes); nR<0): #..as needed.
          discard usleep(500) #; e.write "parc: had to wait\n"
        discard o.uriteBuffer(buf[0].addr, bytes)       # Send body to stdout
      if fds[j].fd != -1 and fds[j].revents != 0:
        if (fds[j].revents and POLLIN) != 0:                # Data is ready
          if (let nR = read(fds[j].fd, rec.addr, rec.sizeof); nR > 0): cp1
          else:
            dec nLive; if close(fds[j].fd)==0: fds[j].fd = -1 else: quit 6
        if (fds[j].revents and POLLHUP) != 0:               # Kid is done
          while (var nR = read(fds[j].fd, rec.addr, rec.sizeof); nR > 0): cp1
          dec nLive; if close(fds[j].fd)==0: fds[j].fd = -1 else: quit 7

proc main() =
  if argc < 2 or argv[1][0] in {'\0', '-'}: quit u
  var buf: string; var st: Stat
  if chdir("/proc") != 0: quit "cannot cd /proc"
  thisUid = getuid()
  for f in getEnv("PARC_PATHS", "sys/kernel/pid_max uptime meminfo").split:
    if f.len > 0: readFile f, buf, st.addr
  i = 1; while i < argc:
    if argv[i][0] in {'1'..'9'}:
      break
    if i mod 2 == 1 and argv[i][0] notin {'s', 'r', 'R'}:
      e.write "Bad command ",$argv[i]," (not s*|r*|R*)\n\n"; quit u, 1
    if i mod 2 == 0 and argv[i][0] != '/':
      e.write "expecting /dirEntry as in /proc/PID/dirEntry\n\n"; quit u, 2
    inc i
  if argv[1][0] != 's':
    e.write "'program' doesn't start w/stat; /smaps_rollup trim may fail\n"
  eoProg = i
  if eoProg mod 2 != 1: quit "unpaired 'program' args", 3
  jobs = getEnv("j", "1").parseInt
  if jobs == 1: perPidWork 0
  else: driveKids()
  rec.clear; rec.nlink = 1                  # At least GNU cpio does this;Cannot
  writeRecHdr cstring("TRAILER!!!"), 10, 0  #..pad w/o seekable(!PIPE) o assump.

main()
