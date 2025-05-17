import std/[syncio, posix, os, strutils], cligen/[posixUt, osUt]

type Rec* {.packed.} = object       # Saved data header; cpio -oHbin compatible
  magic, dev, ino, mode, uid, gid, nlink, rdev: uint16 # magic=0o070707
  mtime : array[2, uint16]
  nmLen : uint16
  datLen: array[2, uint16]              #26B Hdr; Support readFile stat readlink

var rec = Rec(magic: 0o070707)
var pad0: array[512, char]
let o = stdout

proc writeRecHdr(path: cstring; pLen, datLen: int) =
  let path = if path.isNil: nil else: cast[pointer](path)
  let pLen = if path.isNil: 0   else: pLen
  rec.nmLen     = uint16(pLen + 1)      # Include NUL terminator
  rec.datLen[0] = uint16(datLen shr 16)
  rec.datLen[1] = uint16(datLen and 0xFFFF)
  discard o.uriteBuffer(rec.addr, rec.sizeof)
  discard o.uriteBuffer(path    , pLen + 1)
  if pLen mod 2 == 0: discard o.uriteBuffer(pad0.addr, 1)

proc readFile(path: string, buf: var string, st: ptr Stat=nil, perRead=4096) =
  posixUt.readFile path, buf, nil, perRead
  if buf.len > 0:
    rec.mode = 0o100444; rec.nlink = 1  # Regular file r--r--r--; Inherit rest..
    writeRecHdr path.cstring, path.len, buf.len #.. from probable last stat.
    discard o.uriteBuffer(buf.cstring, buf.len)
    if buf.len mod 2 == 1: discard o.uriteBuffer(pad0.addr, 1)

proc stat(a1: cstring, a2: var Stat): cint =
  discard posix.stat(a1, a2)
  rec.dev      = uint16(a2.st_dev)    # Dev should neither change nor matter..
  rec.ino      = uint16(a2.st_ino)    #..so can fold into above for 4B inode.
  rec.mode     = uint16(a2.st_mode)
  rec.uid      = uint16(a2.st_uid)
  rec.gid      = uint16(a2.st_gid)
  rec.nlink    = uint16(a2.st_nlink)  # Generally 1|number of sub-dirs
  rec.rdev     = uint16(a2.st_rdev)   # Dev Specials are very rare
  rec.mtime[0] = uint16(a2.st_mtime.int shr 16)
  rec.mtime[1] = uint16(a2.st_mtime.int and 0xFFFF)
  writeRecHdr a1, a1.len, 0

proc readlink(path: string, err=stderr): string =
  result = posixUt.readlink(path, err)
  if result.len > 0:            # Mark as SymLn;MUST BE KNOWN to be SymLn
    rec.mode = 0o120777; rec.nlink = 1  # Inherit rest from probable last stat.
    writeRecHdr path.cstring, path.len, result.len + 1
    discard o.uriteBuffer(result.cstring, result.len + 1)
    if result.len mod 2 == 0: discard o.uriteBuffer(pad0.addr, 1)

proc add(s: var string, t: cstring, nT: int) =
  let n0 = s.len
  s.setLen n0 + nT
  copyMem s[n0].addr, t, nT

let argc {.importc: "cmdCount".}: cint        # On POSIX, not a lib; importc
let argv {.importc: "cmdLine".}: cstringArray #..is both simpler & faster.
proc cstrlen(s: pointer): int {.importc: "strlen", header: "string.h".}

const u="/proc archiver like cpio -oHbin; Works on '0 len' /proc files. Use:\n"&
 "    parc s / r /io R /exe .. pids >cpio-oHbinOut { s)tat r)ead R)dLn }\n" &
 "$PARC_PATHS is also split-on-space for global(non-perPID) entries done first."

proc main() =
  if argc < 2 or argv[1][0] in {'\0', '-'}: quit u
  var buf: string; var st: Stat
  if chdir("/proc") != 0: quit "cannot cd /proc"
  let thisUid = getuid()
  for f in getEnv("PARC_PATHS", "").split:    # ="sys/kernel/pid_max uptime"
    if f.len > 0: readFile f, buf
  var i = 1; while i < argc:
    if argv[i][0] in {'1'..'9'}:
      break
    if i mod 2 == 1 and argv[i][0] notin {'s', 'r', 'R'}:
      stderr.write "Bad command ",$argv[i]," (not s*|r*|R*)\n\n"; quit u, 1
    if i mod 2 == 0 and argv[i][0] != '/':
      stderr.write "expecting /dirEntry as in /proc/PID/dirEntry\n\n"; quit u, 2
    inc i
  if argv[1][0] != 's': 
    stderr.write "'program' doesn't start w/stat; /smaps_rollup trim may fail\n"
  let eoProg = i
  if eoProg mod 2 != 1: quit "unpaired 'program' args", 3
  var path: string
  while i < argc:
    if argv[i][0] notin {'1'..'9'}:
      stderr.write "parc warning: \"", $argv[i], "\" cannot be a PID\n"
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

main()
