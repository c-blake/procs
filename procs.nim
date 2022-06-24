## Linux /proc data/display/query interfaces - both cmdline & library
#XXX Could port to BSD using libkvm/kvm_getprocs/_getargv/_getenvv/kinfo_proc;
#Requirement analysis just tri-source.  Field presence/semantics may vary a lot.

import std/[os, posix, strutils, sets, tables, terminal, algorithm, nre,
            critbits, parseutils, monotimes],
       cligen/[posixUt, mslice, sysUt, textUt, humanUt, abbrev, macUt]
type
  Proc* = object                ##Abstract proc data (including a kind vector)
    kind*: seq[uint8]             ##kind nums for independent format dimensions
    st*: Stat
    pidPath*: seq[Pid]
    state*: char
    spid*, cmd*, usr*, grp*: string
    pid*, pid0*, ppid0*, pgrp*, sess*, pgid*, nThr*: Pid
    flags*, minflt*, cminflt*, majflt*, cmajflt*: culong
    t0*, ageD*, utime*, stime*, cutime*, cstime*: culong
    prio*, nice*: clong
    vsize*, rss*, rss_rlim*, rtprio*, sched*, blkioTks*, gtime*, cgtime*,
      data0*, data1*, brk0*, arg0*, arg1*, env0*, env1*: culong
    startcode*, endcode*, startstk*, kstk_esp*, kstk_eip*, wchan0*: uint64
    tty*: Dev
    exit_sig*, processor*, exitCode*: cint
    size*, res*, share*, txt*, lib*, dat*, dty*: culong
    environ*, usrs*, grps*: seq[string]
    cmdLine*, root*, cwd*, exe*: string
    name*, umask*, stateS*: string
    tgid*, ngid*, pid1*, ppid*, tracerPid*, nStgid*, nSpid*, nSpgid*, nSsid*:Pid
    uids*: array[4, Uid]  #id_real, id_eff, id_set, id_fs
    gids*: array[4, Gid]  #id_real, id_eff, id_set, id_fs
    groups*: seq[Gid]
    vmPeak*,vmSize*,vmLck*,vmPin*,vmHWM*,vmRSS*, rssAnon*,rssFile*,rssShmem*,
      vmData*, vmStk*, vmExe*, vmLib*, vmPTE*, vmSwap*, hugeTLB*: uint64
    fDSize*, coreDumping*, tHP_enabled*, threads*, noNewPrivs*, seccomp*: uint16
    sigQ*, sigPnd*, shdPnd*, sigBlk*, sigIgn*, sigCgt*: string
    capInh*, capPrm*, capEff*, capBnd*, capAmb*: string
    spec_Store_Bypass*: string
    cpusAllowed*, memsAllowed*: uint16
    cpusAllowedList*, memsAllowedList*: string
    volunCtxtSwitch*, nonVolunCtxtSwitch*: uint64
    wchan*: string
    rch*, wch*, syscr*, syscw*, rbl*, wbl*, wcancel*: uint64
    nIpc*, nMnt*, nNet*, nPid*, nUser*, nUts*, nCgroup*, nPid4Kids*: Ino
    fd0*, fd1*, fd2*, fd3*, fd4*, fd5*, fd6*: string      #/proc/PID/fd/*
    oom_score*, oom_adj*, oom_score_adj*: cint
    #XXX /proc/PID/(personality|limits|..)

  ProcField* = enum                                                     #stat
    pf_pid0=0, pf_cmd, pf_state, pf_ppid0, pf_pgrp, pf_sess, pf_tty, pf_pgid,
    pf_flags, pf_minflt, pf_cminflt, pf_majflt, pf_cmajflt, pf_utime, pf_stime,
    pf_cutime, pf_cstime, pf_prio, pf_nice, pf_nThr, pf_alrm, pf_t0, pf_vsize,
    pf_rss, pf_rss_rlim, pf_startcode, pf_endcode, pf_startstk, pf_kstk_esp,
    pf_kstk_eip,
    pf_sigPnd, pf_sigBlk, pf_sigIgn, pf_sigCgt, #DO NOT USE THESE or pf_alrm
    pf_wchan0, pf_defunct1, pf_defunct2,        #DO NOT USE THESE
    pf_exit_sig, pf_processor, pf_rtprio, pf_sched, pf_blkioTks, pf_gtime,
    pf_cgtime, pf_data0, pf_data1, pf_brk0, pf_arg0, pf_arg1, pf_env0, pf_env1,
    pf_exitCode,
    pffs_uid, pffs_gid,                                                 #fstat
    pffs_usr, pffs_grp, pfs_usrs, pfs_grps,                             #/etc/pw
    pfsm_size,pfsm_res, pfsm_share,pfsm_txt,pfsm_lib,pfsm_dat,pfsm_dty, #statm
    pfcl_cmdline, pfen_environ, pfr_root, pfc_cwd, pfe_exe,             #various
    pfs_name, pfs_umask, pfs_stateS, pfs_tgid, pfs_ngid,                #status
    pfs_pid1, pfs_pPid, pfs_tracerPid, pfs_uids, pfs_gids,
    pfs_fDSize, pfs_groups, pfs_nStgid, pfs_nSpid, pfs_nSpgid, pfs_nSsid,
    pfs_vmPeak, pfs_vmSize, pfs_vmLck, pfs_vmPin, pfs_vmHWM, pfs_vmRSS,
    pfs_rssAnon, pfs_rssFile, pfs_rssShmem,
    pfs_vmData, pfs_vmStk, pfs_vmExe, pfs_vmLib, pfs_vmPTE, pfs_vmSwap,
    pfs_hugeTLB, pfs_coreDumping, pfs_tHP_enabled, pfs_threads,
    pfs_sigQ, pfs_sigPnd, pfs_shdPnd, pfs_sigBlk, pfs_sigIgn, pfs_sigCgt,
    pfs_capInh, pfs_capPrm, pfs_capEff, pfs_capBnd, pfs_capAmb,
    pfs_noNewPrivs, pfs_seccomp, pfs_specStoreBypass,
    pfs_cpusAllowed, pfs_cpusAllowedList,
    pfs_memsAllowed, pfs_memsAllowedList,
    pfs_volunCtxtSwitch, pfs_nonVolunCtxtSwitch,
    pfw_wchan,                                                          #wchan
    pfi_rch, pfi_wch, pfi_syscr, pfi_syscw, pfi_rbl, pfi_wbl, pfi_wcancel, #io
    pfn_ipc, pfn_mnt, pfn_net, pfn_pid, pfn_user, pfn_uts,              #NmSpcs
    pfn_cgroup, pfn_pid4Kids,
    pfd_0, pfd_1, pfd_2, pfd_3, pfd_4, pfd_5, pfd_6,            #/proc/PID/fd/*
    pfo_score, pfo_adj, pfo_score_adj                           #oom scoring
  ProcFields* = set[ProcField]

  ProcSrc = enum psFStat, psStat, psStatm, psStatus, psWChan, psIO
  ProcSrcs* = set[ProcSrc]

  NmSpc* = enum nsIpc  = "ipc" , nsMnt = "mnt", nsNet = "net", nsPid = "pid",
                nsUser = "user", nsUts = "uts", nsCgroup = "cgroup",
                nsPid4Kids = "pid4kids"

  PdAct* = enum acEcho  = "echo", acKill  = "kill", acNice = "nice",
                acWait1 = "wait", acWaitA = "Wait", acCount = "count" #,acList?

  # # # # Types for System-wide data # # # #
  MemInfo* = tuple[MemTotal, MemFree, MemAvailable, Buffers, Cached,
    SwapCached, Active, Inactive, ActiveAnon, InactiveAnon, ActiveFile,
    InactiveFile, Unevictable, Mlocked, SwapTotal, SwapFree, Dirty, Writeback,
    AnonPages, Mapped, Shmem, KReclaimable, Slab, SReclaimable, SUnreclaim,
    KernelStack, PageTables, NFS_Unstable, Bounce, WritebackTmp, CommitLimit,
    Committed_AS, VmallocTotal, VmallocUsed, VmallocChunk, Percpu,
    AnonHugePages, ShmemHugePages, ShmemPmdMapped, CmaTotal, CmaFree,
    HugePagesTotal, HugePagesFree, HugePagesRsvd, HugePagesSurp,
    Hugepagesize, Hugetlb, DirectMap4k, DirectMap2M, DirectMap1G: uint]

  CPUInfo* = tuple[user, nice, system, idle, iowait, irq,
                   softirq, steal, guest, guest_nice: int]
  SoftIRQs* = tuple[all, hi, timer, net_tx, net_rx, blk,
                    irq_poll, tasklet, sched, hrtimer, rcu: int]
  SysStat* = tuple[cpu: seq[CPUInfo],                   ##Index 0=combined
                   interrupts, contextSwitches, bootTime,
                   procs, procsRunnable, procsBlocked: int,
                   softIRQ: SoftIRQs]

  NetStat* = tuple[bytes, packets, errors, drops, fifo, frame,
                   compressed, multicast: int]
  NetDevStat* = tuple[name: string; rcvd, sent: NetStat]
  NetDevStats* = seq[NetDevStat]

  DiskIOStat* = tuple[nIO, nMerge, nSector, msecs: int]
  DiskStat* = tuple[major, minor: int, name: string,
                    reads, writes, cancels: DiskIOStat,
                    inFlight, ioTicks, timeInQ: int]
  DiskStats* = seq[DiskStat]

  LoadAvg* = tuple[m1, m5, m15: string; runnable, total: int; mostRecent: Pid]

  Sys* = tuple[m: MemInfo; s: SysStat; l: LoadAvg; d: DiskStats; n: NetDevStats]

  SysSrc = enum ssMemInfo, ssStat, ssLoadAvg, ssDiskStat, ssNetDev
  SysSrcs* = set[SysSrc]

proc toPfn(ns: NmSpc): ProcField =
  case ns
  of nsIpc:      pfn_ipc
  of nsMnt:      pfn_mnt
  of nsNet:      pfn_net
  of nsPid:      pfn_pid
  of nsUser:     pfn_user
  of nsUts:      pfn_uts
  of nsCgroup:   pfn_cgroup
  of nsPid4Kids: pfn_pid4Kids

const needsStat = { pf_cmd, pf_state, pf_ppid0, pf_pgrp, pf_sess,
  pf_tty, pf_pgid, pf_flags, pf_minflt, pf_cminflt, pf_majflt, pf_cmajflt,
  pf_utime, pf_stime, pf_cutime, pf_cstime, pf_prio, pf_nice, pf_nThr,
  pf_t0, pf_vsize, pf_rss, pf_rss_rlim, pf_startcode, pf_endcode, pf_startstk,
  pf_kstk_esp, pf_kstk_eip, pf_wchan0, pf_exit_sig, pf_processor, pf_rtprio,
  pf_sched }
const needsFstat = { pffs_uid, pffs_gid, pffs_usr, pffs_grp }
const needsStatm = { pfsm_size, pfsm_res, pfsm_share, pfsm_txt, pfsm_lib,
                     pfsm_dat, pfsm_dty }
const needsStatus = { pfs_name, pfs_umask, pfs_stateS, pfs_tgid, pfs_ngid,
  pfs_pid1, pfs_pPid, pfs_tracerPid, pfs_uids, pfs_gids, pfs_fDSize, pfs_groups,
  pfs_nStgid, pfs_nSpid, pfs_nSpgid, pfs_nSsid, pfs_vmPeak, pfs_vmSize,
  pfs_vmLck, pfs_vmPin, pfs_vmHWM, pfs_vmRSS, pfs_rssAnon, pfs_rssFile,
  pfs_rssShmem, pfs_vmData, pfs_vmStk, pfs_vmExe, pfs_vmLib, pfs_vmPTE,
  pfs_vmSwap, pfs_hugeTLB, pfs_coreDumping, pfs_tHP_enabled, pfs_threads,
  pfs_sigQ, pfs_sigPnd, pfs_shdPnd, pfs_sigBlk, pfs_sigIgn, pfs_sigCgt,
  pfs_capInh, pfs_capPrm, pfs_capEff, pfs_capBnd, pfs_capAmb, pfs_noNewPrivs,
  pfs_seccomp, pfs_specStoreBypass, pfs_cpusAllowed,
  pfs_cpusAllowedList, pfs_memsAllowed, pfs_memsAllowedList,
  pfs_volunCtxtSwitch, pfs_nonVolunCtxtSwitch }

var usrs*: Table[Uid, string]      #user tables
var uids*: Table[string, Uid]
var grps*: Table[Gid, string]      #group tables
var gids*: Table[string, Gid]

proc invert*[T, U](x: Table[T, U]): Table[U, T] =
  for k, v in x.pairs: result[v] = k

# # # # # # # PROCESS SPECIFIC /proc/PID/file PARSING # # # # # # #
const needsIO = { pfi_rch, pfi_wch, pfi_syscr, pfi_syscw,
                  pfi_rbl, pfi_wbl, pfi_wcancel }

proc needs*(fill: var ProcFields): ProcSrcs =
  ## Compute the ``ProcDatas`` argument for ``read(var Proc)`` based on
  ## all the requested fields in ``fill``.
  if pffs_usr in fill: fill.incl pffs_uid   #If string usr/grp requested then
  if pffs_grp in fill: fill.incl pffs_gid   #..add the numeric id to fill.
  if pfs_usrs in fill: fill.incl pfs_uids
  if pfs_grps in fill: fill.incl pfs_gids
  if (needsFstat  * fill).card > 0: result.incl psFStat
  if (needsStat   * fill).card > 0: result.incl psStat
  if (needsStatm  * fill).card > 0: result.incl psStatm
  if (needsStatus * fill).card > 0: result.incl psStatus
  if (needsIO     * fill).card > 0: result.incl psIO
  if pffs_usr in fill or pfs_usrs in fill and usrs.len == 0: usrs = users()
  if pffs_grp in fill or pfs_grps in fill and grps.len == 0: grps = groups()

proc nonDecimal(s: string): bool =
  for c in s:
    if c < '0' or c > '9': return true

iterator allPids*(): string =
  ## Yield all pids as strings on a running Linux system via /proc entries
  for pcKind, pid in walkDir("/proc", relative=true):
    if pcKind != pcDir or pid.nonDecimal: continue
    yield pid

proc pidsIt*(pids: seq[string]): auto =
  ## Yield pids as strings from provided ``seq`` if non-empty or ``/proc``.
  result = iterator(): string =
    if pids.len > 0:
      for pid in pids: yield pid
    else:
      for pid in allPids(): yield pid

proc toPid(s: string): Pid   {.inline.} = parseInt(s).Pid
proc toDev(s: string): Dev   {.inline.} = parseInt(s).Dev
proc toCul(s: string, unit=1): culong{.inline.} = parseInt(s).culong*unit.culong
proc toCui(s: string): cuint {.inline.} = parseInt(s).cuint
proc toU16(s: string): uint16{.inline.} = parseInt(s).uint16
proc toU64(s: string, unit=1): uint64{.inline.} = parseInt(s).uint64*unit.uint64
proc toCin(s: string): cint  {.inline.} = parseInt(s).cint
proc toInt(s: string): int   {.inline.} = parseInt(s)
proc toMem(s: string): uint64{.inline.} = parseInt(s).uint64

var buf = newStringOfCap(4096)          #shared IO buffer for all readFile

proc readStat*(p: var Proc; pr: string, fill: ProcFields): bool =
  ## Populate ``Proc p`` pf_ fields requested in ``fill`` via /proc/PID/stat.
  ## Returns false upon missing/corrupt file (eg. stale ``pid`` | not Linux).
  result = true
  (pr & "stat").readFile buf
  let cmd0 = buf.find(" (")             #Bracket command.  Works even if cmd has
  let cmd1 = buf.rfind(") ")            #..parens or whitespace chars in it.
  if cmd0 == -1 or cmd1 == -1 or p.spid != buf[0 ..< cmd0]:
    return false
  if pf_pid0 in fill: p.pid0 = toPid(buf[0 ..< cmd0])
  if pf_cmd  in fill: p.cmd  = buf[cmd0 + 2 ..< cmd1]
  var i = 1
  for s in buf[cmd1 + 2 ..< ^1].split:
    i.inc; case i
    of pf_state    .int:p.state    =if pf_state     in fill: s[0]      else:'\0'
    of pf_ppid0    .int:p.ppid0    =if pf_ppid0     in fill: toPid(s)     else:0
    of pf_pgrp     .int:p.pgrp     =if pf_pgrp      in fill: toPid(s)     else:0
    of pf_sess     .int:p.sess     =if pf_sess      in fill: toPid(s)     else:0
    of pf_tty      .int:p.tty      =if pf_tty       in fill: toDev(s)     else:0
    of pf_pgid     .int:p.pgid     =if pf_pgid      in fill: toPid(s)     else:0
    of pf_flags    .int:p.flags    =if pf_flags     in fill: toCul(s)     else:0
    of pf_minflt   .int:p.minflt   =if pf_minflt    in fill: toCul(s)     else:0
    of pf_cminflt  .int:p.cminflt  =if pf_cminflt   in fill: toCul(s)     else:0
    of pf_majflt   .int:p.majflt   =if pf_majflt    in fill: toCul(s)     else:0
    of pf_cmajflt  .int:p.cmajflt  =if pf_cmajflt   in fill: toCul(s)     else:0
    of pf_utime    .int:p.utime    =if pf_utime     in fill: toCul(s)     else:0
    of pf_stime    .int:p.stime    =if pf_stime     in fill: toCul(s)     else:0
    of pf_cutime   .int:p.cutime   =if pf_cutime    in fill: toCul(s)     else:0
    of pf_cstime   .int:p.cstime   =if pf_cstime    in fill: toCul(s)     else:0
    of pf_prio     .int:p.prio     =if pf_prio      in fill: toInt(s)     else:0
    of pf_nice     .int:p.nice     =if pf_nice      in fill: toInt(s)     else:0
    of pf_nThr     .int:p.nThr     =if pf_nThr      in fill: toPid(s)     else:0
    of pf_alrm     .int: discard #discontinued
    of pf_t0       .int:p.t0       =if pf_t0        in fill: toCul(s)     else:0
    of pf_vsize    .int:p.vsize    =if pf_vsize     in fill: toCul(s)     else:0
    of pf_rss      .int:p.rss      =if pf_rss       in fill: toCul(s,4096)else:0
    of pf_rss_rlim .int:p.rss_rlim =if pf_rss_rlim  in fill: toCul(s)     else:0
    of pf_startcode.int:p.startcode=if pf_startcode in fill: toU64(s)     else:0
    of pf_endcode  .int:p.endcode  =if pf_endcode   in fill: toU64(s)     else:0
    of pf_startstk .int:p.startstk =if pf_startstk  in fill: toU64(s)     else:0
    of pf_kstk_esp .int:p.kstk_esp =if pf_kstk_esp  in fill: toU64(s)     else:0
    of pf_kstk_eip .int:p.kstk_eip =if pf_kstk_eip  in fill: toU64(s)     else:0
    of pf_sigPnd   .int: discard #discontinued
    of pf_sigBlk   .int: discard #discontinued
    of pf_sigIgn   .int: discard #discontinued
    of pf_sigCgt   .int: discard #discontinued
    of pf_wchan0   .int:p.wchan0   =if pf_wchan0    in fill: toU64(s)     else:0
    of pf_defunct1 .int: discard #discontinued
    of pf_defunct2 .int: discard #discontinued
    of pf_exit_sig .int:p.exit_sig =if pf_exit_sig  in fill: toCin(s)     else:0
    of pf_processor.int:p.processor=if pf_processor in fill: toCin(s)     else:0
    of pf_rtprio   .int:p.rtprio   =if pf_rtprio    in fill: toCul(s)     else:0
    of pf_sched    .int:p.sched    =if pf_sched     in fill: toCul(s)     else:0
    of pf_blkioTks .int:p.blkioTks =if pf_blkioTks  in fill: toCul(s)     else:0
    of pf_gtime    .int:p.gtime    =if pf_gtime     in fill: toCul(s)     else:0
    of pf_cgtime   .int:p.cgtime   =if pf_cgtime    in fill: toCul(s)     else:0
    of pf_data0    .int:p.data0    =if pf_data0     in fill: toCul(s)     else:0
    of pf_data1    .int:p.data1    =if pf_data1     in fill: toCul(s)     else:0
    of pf_brk0     .int:p.brk0     =if pf_brk0      in fill: toCul(s)     else:0
    of pf_arg0     .int:p.arg0     =if pf_arg0      in fill: toCul(s)     else:0
    of pf_arg1     .int:p.arg1     =if pf_arg1      in fill: toCul(s)     else:0
    of pf_env0     .int:p.env0     =if pf_env0      in fill: toCul(s)     else:0
    of pf_env1     .int:p.env1     =if pf_env1      in fill: toCul(s)     else:0
    of pf_exitCode .int:p.exitCode =if pf_exitCode  in fill: toCin(s)     else:0
    else: discard

proc readStatm*(p: var Proc; pr: string, fill: ProcFields): bool =
  ## Populate ``Proc p`` pfsm_ fields requested in ``fill`` via /proc/PID/statm.
  ## Returns false upon missing/corrupt file (eg. stale ``pid`` | not Linux).
  result = true
  (pr & "statm").readFile buf
  let c = buf.split
  if c.len != 7:
    return false
  if pfsm_size  in fill: p.size  = toCul(c[0])
  if pfsm_res   in fill: p.res   = toCul(c[1])
  if pfsm_share in fill: p.share = toCul(c[2])
  if pfsm_txt   in fill: p.txt   = toCul(c[3])
  if pfsm_lib   in fill: p.lib   = toCul(c[4])
  if pfsm_dat   in fill: p.dat   = toCul(c[5])
  if pfsm_dty   in fill: p.dty   = toCul(c[6])

proc readStatus*(p: var Proc; pr: string, fill: ProcFields): bool=
  ## Populate ``Proc p`` pfs_ fields requested in ``fill`` via /proc/PID/status.
  ## Returns false upon missing/corrupt file (eg. stale ``pid`` | not Linux).
  proc `<`(f: ProcField, fs: ProcFields): bool {.inline} = f in fs
  result = true
  (pr & "status").readFile buf
  var c = newSeqOfCap[string](32)
  for line in buf.split('\n'):
    if line.len == 0 or line.splitr(c, seps=wspace) < 2: continue
    let n = c[0]
    if   pfs_name       < fill and n=="Name:":       p.name       = c[1]
    elif pfs_umask      < fill and n=="Umask:":      p.umask      = c[1]
    elif pfs_stateS     < fill and n=="State:":      p.stateS     = c[1]
    elif pfs_tgid       < fill and n=="Tgid:":       p.tgid       = toPid(c[1])
    elif pfs_ngid       < fill and n=="Ngid:":       p.ngid       = toPid(c[1])
    elif pfs_pid1       < fill and n=="Pid:":        p.pid1       = toPid(c[1])
    elif pfs_pPid       < fill and n=="PPid:":       p.ppid       = toPid(c[1])
    elif pfs_tracerPid  < fill and n=="TracerPid:":  p.tracerPid  = toPid(c[1])
    elif pfs_uids       < fill and n=="Uid:":
      if c.len != 5: return false
      for i in 0..3: p.uids[i] = toCui(c[i+1]).Uid
    elif pfs_gids       < fill and n=="Gid:":
      if c.len != 5: return false
      for i in 0..3: p.gids[i] = toCui(c[i+1]).Gid
    elif pfs_fDSize     < fill and n=="FDSize:":     p.fDSize     = toU16(c[1])
    elif pfs_groups     < fill and n=="Groups:":
      p.groups.setLen(c.len - 1)
      for i, g in c[1..^1]: p.groups[i] = toCui(g).Gid
    elif pfs_nStgid     < fill and n=="NStgid:":     p.nStgid     = toPid(c[1])
    elif pfs_nSpid      < fill and n=="NSpid:":      p.nSpid      = toPid(c[1])
    elif pfs_nSpgid     < fill and n=="NSpgid:":     p.nSpgid     = toPid(c[1])
    elif pfs_nSsid      < fill and n=="NSsid:":      p.nSsid      = toPid(c[1])
    elif pfs_vmPeak     < fill and n=="VmPeak:":     p.vmPeak     = toMem(c[1])
    elif pfs_vmSize     < fill and n=="VmSize:":     p.vmSize     = toMem(c[1])
    elif pfs_vmLck      < fill and n=="VmLck:":      p.vmLck      = toMem(c[1])
    elif pfs_vmPin      < fill and n=="VmPin:":      p.vmPin      = toMem(c[1])
    elif pfs_vmHWM      < fill and n=="VmHWM:":      p.vmHWM      = toMem(c[1])
    elif pfs_vmRSS      < fill and n=="VmRSS:":      p.vmRSS      = toMem(c[1])
    elif pfs_rssAnon    < fill and n=="RssAnon:":    p.rssAnon    = toMem(c[1])
    elif pfs_rssFile    < fill and n=="RssFile:":    p.rssFile    = toMem(c[1])
    elif pfs_rssShmem   < fill and n=="RssShmem:":   p.rssShmem   = toMem(c[1])
    elif pfs_vmData     < fill and n=="VmData:":     p.vmData     = toMem(c[1])
    elif pfs_vmStk      < fill and n=="VmStk:":      p.vmStk      = toMem(c[1])
    elif pfs_vmExe      < fill and n=="VmExe:":      p.vmExe      = toMem(c[1])
    elif pfs_vmLib      < fill and n=="VmLib:":      p.vmLib      = toMem(c[1])
    elif pfs_vmPTE      < fill and n=="VmPTE:":      p.vmPTE      = toMem(c[1])
    elif pfs_vmSwap     < fill and n=="VmSwap:":     p.vmSwap     = toMem(c[1])
    elif pfs_hugeTLB    < fill and n=="HugetlbPages:":p.hugeTLB    = toMem(c[1])
    elif pfs_coreDumping<fill  and n=="CoreDumping:": p.coreDumping= toU16(c[1])
    elif pfs_tHP_enabled<fill  and n=="THP_enabled:": p.tHP_enabled= toU16(c[1])
    elif pfs_threads    < fill and n=="Threads:":    p.threads    = toU16(c[1])
    elif pfs_sigQ       < fill and n=="SigQ:":       p.sigQ       = c[1]
    elif pfs_sigPnd     < fill and n=="SigPnd:":     p.sigPnd     = c[1]
    elif pfs_shdPnd     < fill and n=="ShdPnd:":     p.shdPnd     = c[1]
    elif pfs_sigBlk     < fill and n=="SigBlk:":     p.sigBlk     = c[1]
    elif pfs_sigIgn     < fill and n=="SigIgn:":     p.sigIgn     = c[1]
    elif pfs_sigCgt     < fill and n=="SigCgt:":     p.sigCgt     = c[1]
    elif pfs_capInh     < fill and n=="CapInh:":     p.capInh     = c[1]
    elif pfs_capPrm     < fill and n=="CapPrm:":     p.capPrm     = c[1]
    elif pfs_capEff     < fill and n=="CapEff:":     p.capEff     = c[1]
    elif pfs_capBnd     < fill and n=="CapBnd:":     p.capBnd     = c[1]
    elif pfs_capAmb     < fill and n=="CapAmb:":     p.capAmb     = c[1]
    elif pfs_noNewPrivs < fill and n=="NoNewPrivs:": p.noNewPrivs = toU16(c[1])
    elif pfs_seccomp    < fill and n=="Seccomp:":    p.seccomp    = toU16(c[1])
    elif pfs_specStoreBypass < fill and n=="Speculation_Store_Bypass:":
      p.spec_Store_Bypass = c[1]
    elif pfs_cpusAllowed<fill and n=="Cpus_allowed:":p.cpusAllowed=toU16(c[1])
    elif pfs_cpusAllowedList < fill and n=="Cpus_allowed_list:":
      p.cpusAllowedList   = c[1]
    elif pfs_memsAllowed<fill and n=="Mems_allowed:":p.memsAllowed=toU16(c[1])
    elif pfs_memsAllowedList < fill and n=="Mems_allowed_list:":
      p.memsAllowedList   = c[1]
    elif pfs_volunCtxtSwitch < fill and n=="voluntary_ctxt_switches:":
      p.volunCtxtSwitch    = toU64(c[1])
    elif pfs_volunCtxtSwitch < fill and n=="nonvoluntary_ctxt_switches:":
      p.nonVolunCtxtSwitch = toU64(c[1])

proc readIO*(p: var Proc; pr: string, fill: ProcFields): bool =
  ## Populate ``Proc p`` pfi_ fields requested in ``fill`` via /proc/PID/io.
  ## Returns false upon missing/corrupt file (eg. stale ``pid`` | not Linux).
  result = true
  (pr & "io").readFile buf
  if buf.len == 0:
    if pfi_rch     in fill: p.rch     = 0
    if pfi_wch     in fill: p.wch     = 0
    if pfi_syscr   in fill: p.syscr   = 0
    if pfi_syscw   in fill: p.syscw   = 0
    if pfi_rbl     in fill: p.rbl     = 0
    if pfi_wbl     in fill: p.wbl     = 0
    if pfi_wcancel in fill: p.wcancel = 0
    return
  var cols = newSeqOfCap[string](2)
  for line in buf.split('\n'):
    if line.len == 0: break
    if line.splitr(cols, sep=' ') != 2: return false
    let nm = cols[0]
    if pfi_rch     in fill and nm == "rchar:"      : p.rch   = toU64(cols[1])
    if pfi_wch     in fill and nm == "wchar:"      : p.wch   = toU64(cols[1])
    if pfi_syscr   in fill and nm == "syscr:"      : p.syscr = toU64(cols[1])
    if pfi_syscw   in fill and nm == "syscw:"      : p.syscw = toU64(cols[1])
    if pfi_rbl     in fill and nm == "read_bytes:" : p.rbl   = toU64(cols[1])
    if pfi_wbl     in fill and nm == "write_bytes:": p.wbl   = toU64(cols[1])
    if pfi_wcancel in fill and nm == "cancelled_write_bytes:":
      p.wcancel = toU64(cols[1])

let devNull* = open("/dev/null", fmWrite)
proc read*(p: var Proc; pid: string, fill: ProcFields, sneed: ProcSrcs): bool =
  ## Omnibus entry point.  Fill ``Proc p`` with fields requested in ``fill`` via
  ## all required ``/proc`` files.  Returns false upon missing/corrupt file (eg.
  ## stale ``pid`` | not Linux).
  result = true                         #Ok unless early exit says elsewise
  let pr = "/proc/" & pid & "/"
  if psFStat in sneed:                  #Must happen before p.st gets used below
    if stat(pr.cstring, p.st) == -1: return false
  p.spid = pid
  p.pid = toPid(pid)
  p.pidPath.setLen 0
  if psStat in sneed and not p.readStat(pr, fill): return false
  if pfcl_cmdline in fill:
    (pr & "cmdline").readFile buf
    p.cmdLine = buf
  if pfen_environ in fill:
    (pr & "environ").readFile buf
    p.environ = buf.split('\0')
  if pfr_root in fill: p.root = readlink(pr & "root", devNull)
  if pfc_cwd  in fill: p.cwd  = readlink(pr & "cwd" , devNull)
  if pfe_exe  in fill: p.exe  = readlink(pr & "exe" , devNull)
  if psStatm  in sneed and not p.readStatm( pr, fill): return false
  if psStatus in sneed and not p.readStatus(pr, fill): return false
  if pfw_wchan in fill: (pr & "wchan").readFile buf; p.wchan = buf
  if psIO in sneed and not p.readIO(pr, fill): return false
  if pffs_usr in fill: p.usr = usrs.getOrDefault(p.st.st_uid, $p.st.st_uid)
  if pffs_grp in fill: p.grp = grps.getOrDefault(p.st.st_gid, $p.st.st_gid)
  if pfs_usrs in fill:
    for ui in p.uids: p.usrs.add usrs.getOrDefault(ui, $ui)
  if pfs_grps in fill:
    for gi in p.gids: p.grps.add grps.getOrDefault(gi, $gi)
  #Maybe faster to readlink, remove tag:[] in tag:[inode], decimal->binary.
  if pfn_ipc      in fill: p.nIpc      = st_inode(pr & "ns/ipc",    devNull)
  if pfn_mnt      in fill: p.nMnt      = st_inode(pr & "ns/mnt",    devNull)
  if pfn_net      in fill: p.nNet      = st_inode(pr & "ns/net",    devNull)
  if pfn_pid      in fill: p.nPid      = st_inode(pr & "ns/pid",    devNull)
  if pfn_user     in fill: p.nUser     = st_inode(pr & "ns/user",   devNull)
  if pfn_uts      in fill: p.nUts      = st_inode(pr & "ns/uts",    devNull)
  if pfn_cgroup   in fill: p.nCgroup   = st_inode(pr & "ns/cgroup", devNull)
  if pfn_pid4Kids in fill:p.nPid4Kids=st_inode(pr&"ns/pid_for_children",devNull)
  if pfd_0 in fill: p.fd0 = readlink(pr & "fd/0", devNull)
  if pfd_1 in fill: p.fd1 = readlink(pr & "fd/1", devNull)
  if pfd_2 in fill: p.fd2 = readlink(pr & "fd/2", devNull)
  if pfd_3 in fill: p.fd3 = readlink(pr & "fd/3", devNull)
  if pfd_4 in fill: p.fd4 = readlink(pr & "fd/4", devNull)
  if pfd_5 in fill: p.fd5 = readlink(pr & "fd/5", devNull)
  if pfd_6 in fill: p.fd6 = readlink(pr & "fd/6", devNull)
  template doInt(x, y, z: untyped) {.dirty.} =
    if x   in fill: (pr & y).readFile buf; z = buf.strip.parseInt.cint
  doInt(pfo_score    , "oom_score"    , p.oom_score    )
  doInt(pfo_adj      , "oom_adj"      , p.oom_adj      )
  doInt(pfo_score_adj, "oom_score_adj", p.oom_score_adj)

proc merge*(p: var Proc; q: Proc, fill: ProcFields, overwriteSetValued=false) =
  ## Merge ``fill`` fields for ``q`` on to those for ``p``.  Summing makes sense
  ## for fields like ``utime``, min|max for eg ``t0``, or bool-aggregated for eg
  ## ``foo``.  When there is no natural aggregation the merged value is really
  ## set-valued (eg, ``tty``).  In such cases, by default, the first Proc wins
  ## the field unless ``overwriteSetValued`` is ``true``.
  if p.pidPath.len > q.pidPath.len: p.pidPath = q.pidPath
  p.ppid0 = if p.pidPath.len > 0: p.pidPath[^1] else: 0
  if pf_minflt              in fill: p.minflt               += q.minflt
  if pf_cminflt             in fill: p.cminflt              += q.cminflt
  if pf_majflt              in fill: p.majflt               += q.majflt
  if pf_cmajflt             in fill: p.cmajflt              += q.cmajflt
  if pf_utime               in fill: p.utime                += q.utime
  if pf_stime               in fill: p.stime                += q.stime
  if pf_cutime              in fill: p.cutime               += q.cutime
  if pf_cstime              in fill: p.cstime               += q.cstime
  if pf_utime               in fill: p.t0 = min(p.t0, q.t0)
  if pf_exitCode            in fill: p.exitCode             += q.exitCode
  if pf_nThr                in fill: p.nThr                 += q.nThr
  if pffs_uid               in fill: p.st.st_uid=min(p.st.st_uid, q.st.st_uid)
  if pffs_gid               in fill: p.st.st_gid=min(p.st.st_gid, q.st.st_gid)
  if pfsm_dty               in fill: p.dty                  += q.dty
  if pfs_threads            in fill: p.threads              += q.threads
  if pfs_vmPeak             in fill: p.vmPeak = max(p.vmPeak, q.vmPeak)
  if pfs_vmHWM              in fill: p.vmHWM  = max(p.vmHWM , q.vmHWM )
  if pfs_vmLck              in fill: p.vmLck                += q.vmLck
  if pfs_vmPin              in fill: p.vmPin                += q.vmPin
  if pfs_volunCtxtSwitch    in fill: p.volunCtxtSwitch      += q.volunCtxtSwitch
  if pfs_nonVolunCtxtSwitch in fill:p.nonVolunCtxtSwitch += q.nonVolunCtxtSwitch
  if pfi_rch                in fill: p.rch                  += q.rch
  if pfi_wch                in fill: p.wch                  += q.wch
  if pfi_syscr              in fill: p.syscr                += q.syscr
  if pfi_syscw              in fill: p.syscw                += q.syscw
  if pfi_rbl                in fill: p.rbl                  += q.rbl
  if pfi_wbl                in fill: p.wbl                  += q.wbl
  if pfi_wcancel            in fill: p.wcancel              += q.wcancel
  if overwriteSetValued: #XXX trickier fields: mem,capabilities,signals,sched,..
    if pf_tty       in fill: p.tty       = q.tty
    if pf_cmd       in fill: p.cmd       = q.cmd
    if pfcl_cmdline in fill: p.cmdLine   = q.cmdLine
    if pfw_wchan    in fill: p.wchan     = q.wchan
    if pf_processor in fill: p.processor = q.processor
    if pffs_usr     in fill: p.usr       = q.usr
    if pffs_grp     in fill: p.grp       = q.grp
    if pfs_name     in fill: p.name      = q.name

proc minusEq*(p: var Proc, q: Proc, fill: ProcFields) =
  ## For temporal differences, set ``p.field -= q`` for all fields in ``fill``
  ## for fields where summing makes sense in ``merge``.
  template doInt(e, f: untyped) {.dirty.} =
    if e in fill: p.f -= q.f
  doInt(pf_rss                , rss               )
  doInt(pf_minflt             , minflt            )
  doInt(pf_cminflt            , cminflt           )
  doInt(pf_majflt             , majflt            )
  doInt(pf_cmajflt            , cmajflt           )
  doInt(pf_utime              , utime             )
  doInt(pf_stime              , stime             )
  doInt(pf_cutime             , cutime            )
  doInt(pf_cstime             , cstime            )
  doInt(pf_exitCode           , exitCode          )
  doInt(pf_nThr               , nThr              )
  doInt(pfsm_size             , size              )
  doInt(pfsm_res              , res               )
  doInt(pfsm_share            , share             )
  doInt(pfsm_txt              , txt               )
  doInt(pfsm_lib              , lib               )
  doInt(pfsm_dat              , dat               )
  doInt(pfsm_dty              , dty               )
  doInt(pfs_threads           , threads           )
  doInt(pfs_vmPeak            , vmPeak            )
  doInt(pfs_vmSize            , vmSize            )
  doInt(pfs_vmLck             , vmLck             )
  doInt(pfs_vmPin             , vmPin             )
  doInt(pfs_vmHWM             , vmHWM             )
  doInt(pfs_vmRSS             , vmRSS             )
  doInt(pfs_rssAnon           , rssAnon           )
  doInt(pfs_rssFile           , rssFile           )
  doInt(pfs_rssShmem          , rssShmem          )
  doInt(pfs_volunCtxtSwitch   , volunCtxtSwitch   )
  doInt(pfs_nonVolunCtxtSwitch, nonVolunCtxtSwitch)
  doInt(pfi_rch               , rch               )
  doInt(pfi_wch               , wch               )
  doInt(pfi_syscr             , syscr             )
  doInt(pfi_syscw             , syscw             )
  doInt(pfi_rbl               , rbl               )
  doInt(pfi_wbl               , wbl               )
  doInt(pfi_wcancel           , wcancel           )

# # # # # # # NON-PROCESS SPECIFIC /proc PARSING # # # # # # #
proc procUptime*(): culong =
  ## System uptime in jiffies (there are 100 jiffies per second)
  "/proc/uptime".readFile buf
  let decimal = buf.find('.')
  if decimal == -1: return
  buf[decimal..decimal+1] = buf[decimal+1..decimal+2]
  buf[decimal+2] = ' '
  var x: int
  discard parseInt(buf, x)
  x.culong

proc procMemInfo*(): MemInfo =
  ## /proc/meminfo fields (in bytes or pages if specified).
  "/proc/meminfo".readFile buf
  proc toU(s: string, unit=1): uint {.inline.} = toU64(s, unit).uint
  var nm = ""
  for line in buf.split('\n'):
    var i = 0
    for col in line.splitWhitespace:
      if i == 0: nm = col
      else:
        if   nm=="MemTotal:"       : result.MemTotal        = toU(col, 1024)
        elif nm=="MemFree:"        : result.MemFree         = toU(col, 1024)
        elif nm=="MemAvailable:"   : result.MemAvailable    = toU(col, 1024)
        elif nm=="Buffers:"        : result.Buffers         = toU(col, 1024)
        elif nm=="Cached:"         : result.Cached          = toU(col, 1024)
        elif nm=="SwapCached:"     : result.SwapCached      = toU(col, 1024)
        elif nm=="Active:"         : result.Active          = toU(col, 1024)
        elif nm=="Inactive:"       : result.Inactive        = toU(col, 1024)
        elif nm=="Active(anon):"   : result.ActiveAnon      = toU(col, 1024)
        elif nm=="Inactive(anon):" : result.InactiveAnon    = toU(col, 1024)
        elif nm=="Active(file):"   : result.ActiveFile      = toU(col, 1024)
        elif nm=="Inactive(file):" : result.InactiveFile    = toU(col, 1024)
        elif nm=="Unevictable:"    : result.Unevictable     = toU(col, 1024)
        elif nm=="Mlocked:"        : result.Mlocked         = toU(col, 1024)
        elif nm=="SwapTotal:"      : result.SwapTotal       = toU(col, 1024)
        elif nm=="SwapFree:"       : result.SwapFree        = toU(col, 1024)
        elif nm=="Dirty:"          : result.Dirty           = toU(col, 1024)
        elif nm=="Writeback:"      : result.Writeback       = toU(col, 1024)
        elif nm=="AnonPages:"      : result.AnonPages       = toU(col, 1024)
        elif nm=="Mapped:"         : result.Mapped          = toU(col, 1024)
        elif nm=="Shmem:"          : result.Shmem           = toU(col, 1024)
        elif nm=="KReclaimable:"   : result.KReclaimable    = toU(col, 1024)
        elif nm=="Slab:"           : result.Slab            = toU(col, 1024)
        elif nm=="SReclaimable:"   : result.SReclaimable    = toU(col, 1024)
        elif nm=="SUnreclaim:"     : result.SUnreclaim      = toU(col, 1024)
        elif nm=="KernelStack:"    : result.KernelStack     = toU(col, 1024)
        elif nm=="PageTables:"     : result.PageTables      = toU(col, 1024)
        elif nm=="NFS_Unstable:"   : result.NFS_Unstable    = toU(col, 1024)
        elif nm=="Bounce:"         : result.Bounce          = toU(col, 1024)
        elif nm=="WritebackTmp:"   : result.WritebackTmp    = toU(col, 1024)
        elif nm=="CommitLimit:"    : result.CommitLimit     = toU(col, 1024)
        elif nm=="Committed_AS:"   : result.Committed_AS    = toU(col, 1024)
        elif nm=="VmallocTotal:"   : result.VmallocTotal    = toU(col, 1024)
        elif nm=="VmallocUsed:"    : result.VmallocUsed     = toU(col, 1024)
        elif nm=="VmallocChunk:"   : result.VmallocChunk    = toU(col, 1024)
        elif nm=="Percpu:"         : result.Percpu          = toU(col, 1024)
        elif nm=="AnonHugePages:"  : result.AnonHugePages   = toU(col, 1024)
        elif nm=="ShmemHugePages:" : result.ShmemHugePages  = toU(col, 1024)
        elif nm=="ShmemPmdMapped:" : result.ShmemPmdMapped  = toU(col, 1024)
        elif nm=="CmaTotal:"       : result.CmaTotal        = toU(col, 1024)
        elif nm=="CmaFree:"        : result.CmaFree         = toU(col, 1024)
        elif nm=="HugePages_Total:": result.HugePagesTotal  = toU(col)
        elif nm=="HugePages_Free:" : result.HugePagesFree   = toU(col)
        elif nm=="HugePages_Rsvd:" : result.HugePagesRsvd   = toU(col)
        elif nm=="HugePages_Surp:" : result.HugePagesSurp   = toU(col)
        elif nm=="Hugepagesize:"   : result.Hugepagesize    = toU(col, 1024)
        elif nm=="Hugetlb:"        : result.Hugetlb         = toU(col, 1024)
        elif nm=="DirectMap4k:"    : result.DirectMap4k     = toU(col, 1024)
        elif nm=="DirectMap2M:"    : result.DirectMap2M     = toU(col, 1024)
        elif nm=="DirectMap1G:"    : result.DirectMap1G     = toU(col, 1024)
        break
      i.inc

proc parseCPUInfo*(rest: string): CPUInfo =
  let col = rest.splitWhitespace
  result.user       = parseInt(col[0])
  result.nice       = parseInt(col[1])
  result.system     = parseInt(col[2])
  result.idle       = parseInt(col[3])
  result.iowait     = parseInt(col[4])
  result.irq        = parseInt(col[5])
  result.softirq    = parseInt(col[6])
  result.steal      = parseInt(col[7])
  result.guest      = parseInt(col[8])
  result.guest_nice = parseInt(col[9])

proc parseSoftIRQs*(rest: string): SoftIRQs =
  let col = rest.splitWhitespace        #"softirq" == [0]
  result.all      = parseInt(col[0])
  result.hi       = parseInt(col[1])
  result.timer    = parseInt(col[2])
  result.net_tx   = parseInt(col[3])
  result.net_rx   = parseInt(col[4])
  result.blk      = parseInt(col[5])
  result.irq_poll = parseInt(col[6])
  result.tasklet  = parseInt(col[7])
  result.sched    = parseInt(col[8])
  result.hrtimer  = parseInt(col[9])
  result.rcu      = parseInt(col[10])

proc procSysStat*(): SysStat =
  for line in lines("/proc/stat"):
    let cols = line.splitWhitespace(maxSplit=1)
    if cols.len != 2: continue
    let nm   = cols[0]
    let rest = cols[1]
    if nm.startsWith("cpu"):    result.cpu.add rest.parseCPUInfo
    elif nm == "intr":          result.interrupts      =
      parseInt(rest.splitWhitespace(maxSplit=1)[0])
    elif nm == "ctxt":          result.contextSwitches = parseInt(rest)
    elif nm == "btime":         result.bootTime        = parseInt(rest)
    elif nm == "processes":     result.procs           = parseInt(rest)
    elif nm == "procs_running": result.procsRunnable   = parseInt(rest)
    elif nm == "procs_blocked": result.procsBlocked    = parseInt(rest)
    elif nm == "softirq":       result.softIRQ         = rest.parseSoftIRQs()

proc parseNetStat*(cols: seq[string]): NetStat =
  result.bytes      = parseInt(cols[0])
  result.packets    = parseInt(cols[1])
  result.errors     = parseInt(cols[2])
  result.drops      = parseInt(cols[3])
  result.fifo       = parseInt(cols[4])
  result.frame      = parseInt(cols[5])
  result.compressed = parseInt(cols[6])
  result.multicast  = parseInt(cols[7])

proc procNetDevStats*(): seq[NetDevStat] =
  var i = 0
  var row: NetDevStat
  for line in lines("/proc/net/dev"):
    i.inc
    if i < 3: continue
    let cols = line.splitWhitespace
    if cols.len < 17:
      stderr.write "unexpected format in /proc/net/dev\n"
      return
    row.name = cols[0]
    if row.name.len > 0 and row.name[^1] == ':':
      row.name.setLen row.name.len - 1
    row.rcvd = parseNetStat(cols[1..8])
    row.sent = parseNetStat(cols[9..16])
    result.add row

proc parseIOStat*(cols: seq[string]): DiskIOStat =
  result.nIO     = parseInt(cols[0])
  result.nMerge  = parseInt(cols[1])
  result.nSector = parseInt(cols[2])
  result.msecs   = parseInt(cols[3])

proc procDiskStats*(): seq[DiskStat] =
  var row: DiskStat
  for line in lines("/proc/diskstats"):
    let cols = line.splitWhitespace
    if cols.len < 18:
      stderr.write "unexpected format in /proc/diskstats\n"
      return
    row.major    = parseInt(cols[0])
    row.minor    = parseInt(cols[1])
    row.name     = cols[2]
    row.reads    = cols[3..6].parseIOStat()
    row.writes   = cols[7..10].parseIOStat()
    row.inFlight = parseInt(cols[11])
    row.ioTicks  = parseInt(cols[12])
    row.timeInQ  = parseInt(cols[13])
    row.cancels  = cols[14..17].parseIOStat()
    result.add row

proc procLoadAvg*(): LoadAvg =
  let cols = readFile("/proc/loadavg").splitWhitespace()
  if cols.len != 5: return
  result.m1         = cols[0]
  result.m5         = cols[1]
  result.m15        = cols[2]
  result.mostRecent = parseInt(cols[4]).Pid
  let runTotal = cols[3].split('/')
  if runTotal.len != 2: return
  result.runnable   = parseInt(runTotal[0])
  result.total      = parseInt(runTotal[1])

# # # # # # # RELATED PROCESS MGMT APIs # # # # # # #
proc usrToUid*(usr: string): Uid =
  ## Convert string|numeric user designations to Uids via usrs
  if usr.len == 0: return 999.Uid
  if usr[0].isDigit: return toInt(usr).Uid
  if usrs.len == 0: usrs = users()
  if usrs.len != 0 and uids.len == 0: uids = usrs.invert
  result = uids.getOrDefault(usr, 999.Uid)
proc usrToUid*(usrs: seq[string]): seq[Uid] =
  for usr in usrs: result.add usrToUid(usr)

proc grpToGid*(grp: string): Gid =
  ## Convert string|numeric group designations to Gids via grps
  if grp.len == 0: return 999.Gid
  if grp[0].isDigit: return toInt(grp).Gid
  if grps.len == 0: grps = groups()
  if grps.len != 0 and gids.len == 0: gids = grps.invert
  result = gids.getOrDefault(grp, 999.Gid)
proc grpToGid*(grps: seq[string]): seq[Gid] =
  for grp in grps: result.add grpToGid(grp)

proc ttyToDev*(tty: string): Dev = #tty string names -> nums
  ## Convert /dev/ttx or ttx to a (Linux) device number
  var st: Stat
  if tty.startsWith('/'): return (if stat(tty, st)==0: st.st_rdev else: 0xFFFF)
  if stat(cstring("/dev/" & tty), st)==0: return st.st_rdev
  if tty.startsWith('t') and tty.len>1 and stat(cstring("/dev/tty" & tty[1..^1]), st)==0:
    return st.st_rdev
  if tty.startsWith('p') and tty.len>1 and stat(cstring("/dev/pts/"&tty[1..^1]), st)==0:
    return st.st_rdev
  return 0xFFFF
proc ttyToDev*(ttys: seq[string]): seq[Dev] = #tty string names -> nums
  for tty in ttys: result.add ttyToDev(tty)

#XXX waitAny & waitAll should obtain pidfds ASAP & use pidfd_send_signal.  pList
#should maybe even become seq[fd].  procs can still die between classification &
#pidfd creation.  Need CLONE_PIDFD/parent-kid relationship for TRUE reliability,
#BUT non-parent-kid relations is actually the main point of this API.
proc waitAny*(pList: seq[Pid], delay: Timespec): int =
  ## Wait for any PIDs in ``pList`` to not exist
  while true:
    for i, pid in pList:
      if kill(pid, 0) == -1 and errno != EPERM: return i
    nanosleep(delay)

proc waitAll*(pList: seq[Pid], delay: Timespec) =
  ## Wait for all PIDs in ``pList`` to not exist at least once
  var failed = newSeq[bool](pList.len)
  var count = 0
  while true:
    for i, pid in pList:
      if not failed[i]:
        if kill(pid, 0) == -1 and errno != EPERM:
          failed[i] = true
          count.inc
    if count == failed.len: return
    nanosleep(delay)

# # # # # # # COMMAND-LINE INTERFACE: display # # # # # # #
type
  Test  = tuple[pfs: ProcFields, test: proc(p:var Proc):bool]      #unattributed
  Kind  = tuple[attr:string, kord:uint8, test:proc(p:var Proc):bool]
  Cmp   = tuple[sgn: int, cmp: proc(x, y: ptr Proc): int]          #1-level cmp
  Field = tuple[prefix: string; left: bool; wid: int; c: char; hdr: string,
                fmt: proc(p: var Proc, wMax=0): string]            #1-field fmt
  KindDim = tuple[k, d: uint8]

  DpCf* = object  #User set/cfg fields early; Computed/intern fields after pids.
    kind*, colors*, color*, ageFmt*: seq[string]            ##usrDefd kind/colrs
    incl*, excl*, merge*, hdrs*: seq[string]                ##usrDefd filt,aggr
    order*, diffCmp*, format*, maxUnm*, maxGnm*: string     ##see help string
    indent*, width*: int                                    ##termWidth override
    delay*: Timespec
    wide*, binary*, plain*, header*, realIds*: bool         ##flags; see help
    pids*: seq[string]                                      ##pids to display
    t0: Timespec                                            #ref time for pTms
    kinds: seq[Kind]                                        #kinds user colors
    ukind: seq[seq[uint8]]                                  #USED kind dim seqs
    sin, sex: set[uint8]                                    #compiled filters
    nin, nex: int                                           #fast cardinality
    cmps, diffCmps: seq[Cmp]                                #compares for sort
    fields: seq[Field]                                      #fields to format
    mergeKDs: HashSet[KindDim]                              #kinds to merge
    need, diff: ProcFields                                  #fieldNeeds(above 6)
    sneed: ProcSrcs                                         #dataNeeds(above)
    uidNeeds, gidNeeds, usrNeeds, grpNeeds: ProcFields      #allow id src swtch
    forest, needKin, needUptm, needTotRAM: bool             #flags
    uptm: culong
    totRAM: uint64
    tmFmtL, tmFmtU, tmFmtP: seq[tuple[age:int, fmt:string]] #(age,tFmt)lo/up/pln
    uAbb, gAbb: Abbrev
    a0, attrDiff: string                                    #if plain: ""
    attrSize: array[0..25, string]  #CAP letter-indexed with ord(x) - ord('A')
    tests: CritBitTree[Test]
    kslot: CritBitTree[tuple[slot:uint8, pfs:ProcFields, dim:int]] #for filters
    kslotNm: seq[string]                                    #Inverse of above

var cg: ptr DpCf            #Lazy way out of making many little procs take DpCf
var cmpsG: ptr seq[Cmp]

###### BUILT-IN CLASSIFICATION TESTS
var builtin: CritBitTree[Test]
template tAdd(name, pfs, t: untyped) {.dirty.} =
  builtin[name] = (pfs, proc(p: var Proc): bool {.closure.} = t)
tAdd("unknown", {}): true
tAdd("sleep", {pf_state} ): p.state in { 'S', 'I' }
tAdd("run"  , {pf_state} ): p.state in { 'R', 'D' }
tAdd("stop" , {pf_state} ): p.state in { 'T', 't' }
tAdd("zomb" , {pf_state} ): p.state == 'Z'
tAdd("niced", {pf_nice}  ): p.nice != 0
tAdd("MT"   , {pf_nThr}  ): p.nThr > 1
tAdd("L"    , {pfs_vmLck}): p.vmLck > 0'u64
tAdd("kern" , {pf_ppid0} ): p.pid == 2 or p.ppid0 == 2

proc cmdClean(cmd: string): string =
  result.setLen cmd.len
  for i, c in cmd:
    result[i] = if ord(c) < 32: ' ' else: c
  while result[^1] == ' ':
    result.setLen result.len - 1

###### USER-DEFINED CLASSIFICATION TESTS
proc testPCRegex(rxes: seq[Regex], p: var Proc): bool =
  result = false
  for r in rxes:
    if p.cmd.contains(r): return true

proc getUid(p: Proc): Uid    = (if cg.realIds: p.uids[0] else: p.st.st_uid)
proc getGid(p: Proc): Gid    = (if cg.realIds: p.gids[0] else: p.st.st_gid)
proc getUsr(p: Proc): string = (if cg.realIds: p.usrs[0] else: p.usr      )
proc getGrp(p: Proc): string = (if cg.realIds: p.grps[0] else: p.grp      )

proc testOwnId[Id](owns: HashSet[Id], p: var Proc): bool =
  when Id is Uid: p.getUid in owns
  else          : p.getGid in owns
proc testUsr(nms: HashSet[string], p: var Proc): bool = p.usr in nms
proc testGrp(nms: HashSet[string], p: var Proc): bool = p.grp in nms

proc testAll(tsts: seq[Test], p: var Proc): bool =
  result = true
  for i, t in tsts:
    if not(t.test p): return false

proc testAny(tsts: seq[Test], p: var Proc): bool =
  for t in tsts:
    if t.test p: return true

proc testNone(tsts: seq[Test], p: var Proc): bool =
  result = true
  for t in tsts:
    if t.test p: return false

proc addPCRegex(cf: var DpCf; nm, s: string) =      #Q: add flags/modes?
  var rxes: seq[Regex]
  for pattern in s.splitWhitespace: rxes.add pattern.re
  cf.tests[nm] = ({pf_cmd}, proc(p: var Proc): bool = rxes.testPCRegex p)

proc addOwnId(cf: var DpCf; md: char; nm, s: string) =
  var s: HashSet[Uid] | HashSet[Gid] = if md == 'u': s.splitWhitespace.toUidSet
                                       else: s.splitWhitespace.toGidSet
  let depends = if md == 'u': cf.uidNeeds else: cf.gidNeeds
  cf.tests[nm] = (depends, proc(p: var Proc): bool = s.testOwnId(p))

proc addOwner(cf: var DpCf; md: char; nm, s: string) =
  var s = s.splitWhitespace.toHashSet
  if md == 'u':
    cf.tests[nm] = (cf.usrNeeds, proc(p: var Proc): bool = s.testUsr(p))
  else:
    cf.tests[nm] = (cf.grpNeeds, proc(p: var Proc): bool = s.testGrp(p))

proc addCombo(cf: var DpCf; tester: auto; nm, s: string) =
  var tsts: seq[Test]
  var pfs: ProcFields
  for t in s.splitWhitespace:
    try:
      let tt = cf.tests[t]; tsts.add tt; pfs = pfs + tt.pfs
    except: raise newException(ValueError, "bad kind: \"" & t & "\"")
  cf.tests[nm] = (pfs, proc(p: var Proc): bool = tester(tsts, p))

proc parseKind(cf: var DpCf) =
  for kin in cf.kind:
    let col = kin.splitWhitespace(maxsplit=2)
    if col.len < 3: raise newException(ValueError, "bad kind: \"" & kin & "\"")
    if   col[1] == "pcr": cf.addPCRegex(col[0], col[2])
    elif col[1].endsWith("id"):cf.addOwnId(col[1][0].toLowerAscii,col[0],col[2])
    elif col[1] == "usr": cf.addOwner(col[1][0], col[0], col[2])
    elif col[1] == "grp": cf.addOwner(col[1][0], col[0], col[2])
    elif col[1] == "any": cf.addCombo(testAny, col[0], col[2])
    elif col[1] == "all": cf.addCombo(testAll, col[0], col[2])
    elif col[1] == "none": cf.addCombo(testNone, col[0], col[2])
    else: raise newException(ValueError, "bad kind: \"" & kin & "\"")

proc parseColor(cf: var DpCf) =
  var unknown = 255.uint8
  for spec in cf.color:
    let cols = spec.splitWhitespace()
    if cols.len<2: raise newException(ValueError, "bad color: \"" & spec & "\"")
    let nmKoD = cols[0].split(':')
    let nm    = nmKoD[0].strip()
    let ko    = (if nmKoD.len>1: parseHexInt(nmKoD[1].strip()) else: 255).uint8
    let dim   = if nmKoD.len>2: parseInt(nmKoD[2].strip()) else: 0
    let attrs = textAttrOn(cols[1..^1], cf.plain)
    try:
      let ok = nm.len == 5 and (nm.startsWith("size") or nm == "delta")
      let (k, test) = cf.tests.match(nm, "kind", if ok: nil else: stderr)
      let kno  = cf.kinds.len.uint8               #Found test; add to used kinds
      cf.kslot[k] = (kno, test.pfs, dim)          #Record kind num, ProcFields
      add(cf.kinds, (attr: attrs, kord: ko, test: test.test))
      if dim + 1 > cf.ukind.len: cf.ukind.setLen(dim + 1)
      cf.ukind[dim].add kno
      cf.need = cf.need + test.pfs
      if nm == "unknown": unknown = kno
    except KeyError:
      if nm.len == 5:
        if nm[0..3]=="size" and nm[4] in {'B','K','M','G','T'}:
          cf.attrSize[ord(nm[4]) - ord('A')] = attrs
        elif nm == "delta":
          cf.attrDiff = attrs
      else:
        raise newException(ValueError, "unknown color key: \"" & nm & "\"")
  if unknown == 255:  #Terminate .kinds if usr did not specify attrs for unknown
   add(cf.kinds, ("", 255.uint8, cf.tests["unknown"].test))
  cf.kslotNm.setLen cf.kslot.len                 #Build inverse table:
  for nm,val in cf.kslot:                        #  kind slots -> names
    cf.kslotNm[val.slot] = nm

###### FILTERING
proc compileFilter(cf: var DpCf, spec: seq[string], msg: string): set[uint8] =
  for nm in spec:
    try:
      let k = cf.kslot.match(nm, "colored kind").val
      result.incl(k.slot)
      cf.need = cf.need + k.pfs
      cf.needKin = true   #must fully classify if any kind is used as a filter
    except: raise newException(ValueError, msg & " name \"" & nm & "\"")

proc parseFilters(cf: var DpCf) =
  cf.sin = cf.compileFilter(cf.incl, "incl filter"); cf.nin = cf.sin.card
  cf.sex = cf.compileFilter(cf.excl, "excl filter"); cf.nex = cf.sex.card

proc contains(s: set[uint8], es: seq[uint8]): bool =
  for e in es:
    if e in s: return true

proc classify(cf: DpCf, p: var Proc, d: int): uint8 = #assign format kind [d]
  result = (cf.kinds.len - 1).uint8                   #all d share unknown slot
  for i, k in cf.ukind[d]:
    if cf.kinds[k].test(p): return k.uint8

proc failsFilters(cf: DpCf; p: var Proc): bool =
  if cf.needKin:
    p.kind = newSeq[uint8](cf.ukind.len)
    for d in 0 ..< cf.ukind.len:
      p.kind[d] = cf.classify(p, d)
  (cf.nex > 0 and p.kind in cf.sex) or (cf.nin > 0 and p.kind notin cf.sin)

###### SORTING
proc cmp[T](x, y: seq[T]): int {.procvar.} =
  let n = min(x.len, y.len)
  for i in 0 ..< n:
    if x[i] != y[i]: return x[i] - y[i]
  return x.len - y.len

var cmpOf: Table[char, tuple[pfs: ProcFields, cmp: proc(x, y: ptr Proc): int]]
template cAdd(code, pfs, cmpr, T, data: untyped) {.dirty.} =
  cmpOf[code] = (pfs, proc(a, b: ptr Proc): int {.closure.} =
                   proc get(p: Proc): T = data
                   cmpr(get(a[]), get(b[])))
cAdd('p', {}                   , cmp, Pid     ): p.pid
cAdd('c', {pf_cmd}             , cmp, string  ): p.cmd
cAdd('C', {pfcl_cmdline,pf_cmd}, cmp, string  ):
  if p.cmdLine.len > 0: p.cmdLine.cmdClean else: p.cmd
cAdd('u', {pffs_uid}           , cmp, Uid     ): p.getUid
cAdd('U', {pffs_gid}           , cmp, string  ): p.getUsr
cAdd('z', {pffs_usr}           , cmp, Gid     ): p.getGid
cAdd('Z', {pffs_grp}           , cmp, string  ): p.getGrp
cAdd('D', {pf_ppid0}           , cmp, seq[Pid]): p.pidPath
cAdd('P', {pf_ppid0}           , cmp, Pid     ): p.ppid0
cAdd('n', {pf_nice}            , cmp, clong   ): p.nice
cAdd('y', {pf_prio}            , cmp, clong   ): p.prio
cAdd('w', {pfw_wchan}          , cmp, string  ): p.wchan
cAdd('s', {pf_state}           , cmp, char    ): p.state
cAdd('t', {pf_tty}             , cmp, Dev     ): p.tty
cAdd('T', {pf_t0}              , cmp, culong  ): p.t0
cAdd('a', {pf_t0}              , cmp, culong  ): cg.uptm - p.t0
cAdd('j', {pf_utime,pf_stime}  , cmp, culong  ): p.utime  + p.stime
cAdd('J', {pf_utime,pf_stime, pf_cutime,pf_cstime}, cmp, culong):
                                 p.utime + p.cutime + p.stime + p.cstime
cAdd('e', {pf_utime,pf_stime}  , cmp, culong  ): p.utime + p.stime
cAdd('E', {pf_utime,pf_stime, pf_cutime,pf_cstime}, cmp, culong):
                                 p.utime + p.cutime + p.stime + p.cstime
cAdd('L', {pf_flags}           , cmp, culong  ): p.flags
cAdd('v', {pf_vsize}           , cmp, culong  ): p.vsize
cAdd('d', {pf_vsize, pf_startcode, pf_endcode}, cmp, uint64):
                                 p.vsize.uint64 + (p.startcode - p.endcode)
cAdd('r', {pf_vsize, pf_startcode, pf_endcode}, cmp, uint64):
  if p.vsize != 0: p.vsize.uint64 + p.startcode - p.endcode else: 0
cAdd('R', {pf_rss}             , cmp, culong  ): p.rss #p.vmRSS?
cAdd('f', {pf_minflt}          , cmp, culong  ): p.minflt
cAdd('F', {pf_majflt}          , cmp, culong  ): p.majflt
cAdd('h', {pf_minflt,pf_cminflt},cmp, culong  ): p.minflt + p.cminflt
cAdd('H', {pf_majflt,pf_cmajflt},cmp, culong  ): p.majflt + p.cmajflt
cAdd('g', {pf_pgrp}            , cmp, Pid     ): p.pgrp
cAdd('o', {pf_sess}            , cmp, Pid     ): p.sess
cAdd('G', {pf_pgid}            , cmp, Pid     ): p.pgid
cAdd('K', {pf_startstk}        , cmp, uint64  ): p.startstk
cAdd('S', {pf_kstk_esp}        , cmp, uint64  ): p.kstk_esp
cAdd('I', {pf_kstk_eip}        , cmp, uint64  ): p.kstk_eip
cAdd('Q', {pfs_sigQ}           , cmp, string  ): p.sigQ
cAdd('q', {pfs_sigPnd}         , cmp, string  ): p.sigPnd
cAdd('X', {pfs_shdPnd}         , cmp, string  ): p.shdPnd
cAdd('B', {pfs_sigBlk}         , cmp, string  ): p.sigBlk
cAdd('i', {pfs_sigIgn}         , cmp, string  ): p.sigIgn
cAdd('x', {pfs_sigCgt}         , cmp, string  ): p.sigCgt
cAdd('0', {pfd_0}              , cmp, string  ): p.fd0
cAdd('1', {pfd_1}              , cmp, string  ): p.fd1
cAdd('2', {pfd_2}              , cmp, string  ): p.fd2
cAdd('3', {pfd_3}              , cmp, string  ): p.fd3
cAdd('4', {pfd_4}              , cmp, string  ): p.fd4
cAdd('5', {pfd_5}              , cmp, string  ): p.fd5
cAdd('6', {pfd_6}              , cmp, string  ): p.fd6
cAdd('<', {pfi_rch}            , cmp, uint64  ): p.rch # ,pfi_rbl + p.rbl
cAdd('>', {pfi_wch}            , cmp, uint64  ): p.wch # ,pfi_wbl + p.wbl
cAdd('O', {pfo_score}          , cmp, cint    ): p.oom_score

proc parseOrder(order: string, cmps: var seq[Cmp], need: var ProcFields): bool =
  cmps.setLen(0)
  if order == "-": return
  var sgn = +1
  var cmpEntry: tuple[pfs: ProcFields, cmp: proc(x, y: ptr Proc): int]
  for c in order:
    if   c == '-': sgn = -1; continue
    elif c == '+': sgn = +1; continue
    try   : cmpEntry = cmpOf[c]
    except: raise newException(ValueError, "unknown sort key code " & c.repr)
    cmps.add((sgn, cmpEntry.cmp))
    need = need + cmpEntry.pfs
    if c == 'a': result = true
    sgn = +1

proc multiLevelCmp(a, b: ptr Proc): int {.procvar.} =
  for i in 0 ..< cmpsG[].len:
    let val = cmpsG[][i].cmp(a, b)
    if val != 0: return cmpsG[][i].sgn * val
  return 0

###### FORMATTING ENGINE
proc parseAge(cf: var DpCf) =
  template hl(sp, co, pl): auto {.dirty.} = specifierHighlight(sp, co, pl)
  for aFs in cf.ageFmt:
    let aF = aFs.split('@')
    if aF.len != 2: raise newException(ValueError, "bad ageFmt:\"" & aFs & "\"")
    if aF[0].startsWith('+'):   #2**31 =~ 68 yrs in future from when fin is run.
     try   : cf.tmFmtU.add((parseInt(aF[0]), hl(aF[1], strftimeCodes,cf.plain)))
     except: cf.tmFmtU.add((-2147483648.int, hl(aF[1], strftimeCodes,cf.plain)))
    elif aF[0].startsWith('-'): #plain mode formats
     try:    cf.tmFmtP.add((-parseInt(aF[0]),hl(aF[1], strftimeCodes,cf.plain)))
     except: cf.tmFmtP.add((-2147483648.int, hl(aF[1], strftimeCodes,cf.plain)))
    else:
     try   : cf.tmFmtL.add((parseInt(aF[0]), hl(aF[1], strftimeCodes,cf.plain)))
     except: cf.tmFmtL.add((-2147483648.int, hl(aF[1], strftimeCodes,cf.plain)))

proc kattr(p: Proc): string =
  for e in p.kind: result.add cg.kinds[e].attr

proc `-`*(b, a: Timespec): Timespec =
  let nsec =  b.tv_sec.int64 * 1_000_000_000 + b.tv_nsec.int64 -
             (a.tv_sec.int64 * 1_000_000_000 + a.tv_nsec.int64)
  result.tv_sec  = (nsec div 1_000_000_000).Time
  result.tv_nsec = (nsec mod 1_000_000_000).clong

proc fmtTime(ts: Timespec): string =
  let tfs = if cg.plain: cg.tmFmtP else: cg.tmFmtL
  let pAge = (cg.t0.tv_sec - ts.tv_sec).int   #ns can only make pAge off by <=1s
  for (age, fmt) in tfs:
    if pAge >= age:
      return if fmt[0] != '/': strftime(fmt, ts)
             else: pAge.humanDuration(fmt[1..^1], cg.plain)
  strftime(if tfs.len > 0: tfs[^1][1] else: "%F:%T.%3", ts)

proc fmtJif(jiffies: culong): string =
  for (age, fmt) in cg.tmFmtU:
    if jiffies.int >= age:
      return jiffies.int.humanDuration(fmt[1..^1], cg.plain)
  $jiffies

proc fmtSz[T](attrSize: array[0..25, string], a0: string, binary: bool, b: T,
              wid=4): string {.inline.} =
  proc sizeFmt(sz: string): string =          #colorized metric-byte sizes
    let ix   = (if sz[^1] in Digits: 'B'.ord else: sz[^1].ord) - 'A'.ord
    let digs = sz.find Digits
    sz[0 ..< digs] & attrSize[ix] & sz[digs..^1] & a0
  if b.uint64 > 18446744073709551606'u64: "-" else:
    sizeFmt(align(humanReadable4(b.uint, binary), wid))

proc fmtSz[T](b: T): string = fmtSz(cg.attrSize, cg.a0, cg.binary, b, 4)

proc fmtPct[A,B](n: A, d: B): string =
  if d.uint64 == 0: return "?"
  let mills = (1000.uint64 * n.uint64 + 5) div d.uint64
  let leading = mills div 10
  if leading < 100: $leading & '.' & $(mills mod 10) else: $leading

var fmtCodes: set[char]   #left below is just dflt alignment. User can override.
var fmtOf: Table[char, tuple[pfs: ProcFields; left: bool; wid: int; hdr: string;
                 fmt: proc(x: var Proc, wMax=0): string]]
template fAdd(code, pfs, left, wid, hdr, toStr: untyped) {.dirty.} =
  fmtCodes.incl(code)
  fmtOf[code] = (pfs, left.bool, wid, hdr,
                 proc(p:var Proc, wMax=0): string {.closure.} = toStr)
fAdd('p', {}                   ,0,5, "PID"    ): p.spid
fAdd('c', {pf_cmd}             ,1,-1,"CMD"    ):
  if cg.wide: p.cmd else: p.cmd[0 ..< min(p.cmd.len, wMax)]
fAdd('C', {pfcl_cmdline,pf_cmd},1,-1,"COMMAND"):
  let s = if p.cmdLine.len > 0: p.cmdLine.cmdClean else: p.cmd
  if cg.wide: s else: s[0 ..< min(s.len, wMax)]
fAdd('u', {pffs_uid}           ,0,5, "UID"    ): $p.getUid.uint
fAdd('U', {pffs_gid}           ,1,4, "USER"   ): cg.uAbb.abbrev p.getUsr
fAdd('z', {pffs_usr}           ,0,5, "GID"    ): $p.getGid.uint
fAdd('Z', {pffs_grp}           ,1,4, "GRP"    ): cg.gAbb.abbrev p.getGrp
#Unshowable: pf_nThr,pf_rss_rlim,pf_exit_sig,pf_processor,pf_rtprio,pf_sched
fAdd('D', {pf_ppid0}           ,0,-1, ""      ):        #Below - 1 to show init&
  let s = repeat(' ', cg.indent*max(0,p.pidPath.len-2)) #..kthreadd as sep roots
  if cg.wide: s else: s[0 ..< min(s.len, max(0, wMax - 1))]
fAdd('P', {pf_ppid0}           ,0,5, "PPID"   ): $p.ppid0
fAdd('n', {pf_nice}            ,0,7, "NI"     ): $p.nice
fAdd('y', {pf_prio}            ,0,4, "PRI"    ): $p.prio
fAdd('w', {pfw_wchan}          ,1,9, "WCHAN"  ):
  let wch = if p.wchan.startsWith("__x64_sys_"): p.wchan[10..^1] else: p.wchan
  wch[0 ..< min(9,wch.len)]
fAdd('s', {pf_state}           ,0,4, "STAT"   ): $p.state
fAdd('t', {pf_tty}             ,1,3, "TTY"    ):
        if   p.tty shr 8 == 0x04: "t" & $(p.tty and 0xFF) #Linux VTs
        elif p.tty shr 8 == 0x88: "p" & $(p.tty and 0xFF) #pseudo-terminals
        else: "?"                                         #no tty/unknown
fAdd('a', {pf_t0}              ,0,4, "AGE"    ): fmtJif(cg.uptm - p.t0)
fAdd('T', {pf_t0}              ,1,6, "START"  ):
  let ageJ = cg.uptm - p.t0
  var age = Timespec(tv_sec: (ageJ div 100).Time,
                     tv_nsec: (ageJ mod 100).clong * 100_000_000)
  fmtTime(cg.t0 - age)
fAdd('j', {pf_utime,pf_stime}  ,0,4, "TIME"   ): fmtJif(p.utime + p.stime)
fAdd('J', {pf_utime,pf_stime,pf_cutime,pf_cstime},0,4, "CTIM"):
  fmtJif(p.utime + p.stime + p.cutime + p.cstime)
fAdd('e', {pf_utime,pf_stime}  ,0,4, "%cPU"   ): fmtPct(p.utime+p.stime,p.ageD)
fAdd('E', {pf_utime,pf_stime,pf_cutime,pf_cstime},0,4, "%CPU"):
  fmtPct(p.utime + p.stime + p.cutime + p.cstime, p.ageD)
fAdd('m', {pf_rss}             ,0,4, "%MEM"   ): fmtPct(p.rss, cg.totRAM)
fAdd('L', {pf_flags}           ,1,7, "F"      ): "x"&toHex(p.flags.BiggestInt,6)
fAdd('v', {pf_vsize}           ,0,4, "VSZ"    ): fmtSz(p.vsize)
fAdd('d', {pf_vsize,pf_startcode,pf_endcode},0,4, "DRS"):
  fmtSz(if p.vsize.int != 0: p.vsize.uint64 + p.startcode - p.endcode else: 0)
fAdd('r', {pf_vsize,pf_startcode,pf_endcode},0,4, "TRS"):
  fmtSz(if p.vsize.int != 0: p.endcode - p.startcode else: 0)
fAdd('R', {pf_rss}             ,0,4, "RSS"    ): fmtSz(p.rss)
fAdd('f', {pf_minflt}          ,0,4, "MNFL"   ): fmtSz(p.minflt)
fAdd('F', {pf_majflt}          ,0,4, "MJFL"   ): fmtSz(p.majflt)
fAdd('h', {pf_minflt,pf_cminflt},0,4,"CMNF"   ): fmtSz(p.minflt + p.cminflt)
fAdd('H', {pf_majflt,pf_cmajflt},0,4,"CMJF"   ): fmtSz(p.majflt + p.cmajflt)
fAdd('g', {pf_pgrp}            ,0,5, "PGID"   ): $p.pgrp
fAdd('o', {pf_sess}            ,0,5, "SID"    ): $p.sess
fAdd('G', {pf_pgid}            ,0,5, "TPGID"  ): $p.pgid
fAdd('e', {pfen_environ}       ,1,5, "ENVIRON"): p.environ.join(" ")
fAdd('K', {pf_startstk}        ,1,16,"STACK"  ): $p.startstk
fAdd('S', {pf_kstk_esp}        ,1,16,"ESP"    ): $p.kstk_esp
fAdd('I', {pf_kstk_eip}        ,1,16,"EIP"    ): $p.kstk_eip
fAdd('Q', {pfs_sigQ}           ,1,8, "SIGQ"   ): p.sigQ
fAdd('q', {pfs_sigPnd}         ,1,16,"PENDING"): p.sigPnd
fAdd('X', {pfs_shdPnd}         ,1,16,"SHDPND" ): p.shdPnd
fAdd('B', {pfs_sigBlk}         ,1,16,"BLOCKED"): p.sigBlk
fAdd('i', {pfs_sigIgn}         ,1,16,"IGNORED"): p.sigIgn
fAdd('x', {pfs_sigCgt}         ,1,16,"CAUGHT" ): p.sigCgt
fAdd('0', {pfd_0}              ,1,3, "FD0"    ): p.fd0
fAdd('1', {pfd_1}              ,1,3, "FD1"    ): p.fd1
fAdd('2', {pfd_2}              ,1,3, "FD2"    ): p.fd2
fAdd('3', {pfd_3}              ,1,3, "FD3"    ): p.fd3
fAdd('4', {pfd_4}              ,1,3, "FD4"    ): p.fd4
fAdd('5', {pfd_5}              ,1,3, "FD5"    ): p.fd5
fAdd('6', {pfd_6}              ,1,3, "FD6"    ): p.fd6
fAdd('<', {pfi_rch}            ,0,4, "READ"   ): fmtSz(p.rch) # ,pfi_rbl + p.rbl
fAdd('>', {pfi_wch}            ,0,4, "WRIT"   ): fmtSz(p.wch) # ,pfi_wbl + p.wbl
fAdd('O', {pfo_score}          ,0,4, "OOMs"   ): $p.oom_score

proc parseFormat(cf: var DpCf) =
  let format = if cf.format.len > 0: cf.format
               else: "%{bold}p %{italic}s %{inverse}R %{underline}J %c"
  type State = enum inPrefix, inField
  var leftMost = true; var algn = '\0'
  var state = inPrefix
  var prefix = ""
  var fmtE: tuple[pfs: ProcFields; left: bool; wid: int; hdr: string,
                  fmt: proc(p: var Proc, wMax=0): string]
  cf.fields.setLen(0)
  for c in specifierHighlight(format, fmtCodes, cf.plain):
    case state
    of inField:
      if c in {'-', '+'}: algn = c; continue  #Any number of 'em;Last one wins
      state = inPrefix
      try   : fmtE = fmtOf[c]
      except: raise newException(ValueError, "unknown format code " & c.repr)
      let leftAlign = if algn != '\0': algn == '-' #User spec always wins else..
                      else:                        #..1st col left&field default
                        if leftMost: true else: fmtE.left
      cf.fields.add((prefix, leftAlign, fmtE.wid, c, fmtE.hdr, fmtE.fmt))
      leftMost = false; algn = '\0'
      prefix = ""
      cf.need = cf.need + fmtE.pfs
      if   c == 'U': cf.need.incl pffs_usr
      elif c == 'G': cf.need.incl pffs_grp
      elif c == 'D': cf.forest = true
      elif c in {'T', 'a', 'e', 'E'}: cf.needUptm = true
      elif c in {'m'}: cf.needTotRAM = true
    of inPrefix:
      if c == '%':
        state = inField
        continue
      prefix.add(c)

proc parseMerge(cf: var DpCf) =
  for nm in cf.merge:
    try:
      let k = cf.kslot.match(nm, "color/merge kind").val
      cf.mergeKDs.incl (k.slot, k.dim.uint8)
      cf.need = cf.need + k.pfs
      cf.needKin = true   #classify all if any kind is used as a merge
    except:
      raise newException(ValueError, " name \"" & nm & "\"")

proc parseHdrs(cf: var DpCf) =
  for chHdr in cf.hdrs:
    let cols = chHdr.split(':')
    if cols.len != 2:
      raise newException(ValueError, "No ':' separator in " & chHdr)
    for i, f in cf.fields:    #Just ignore unknown char codes since format
      if f.c == cols[0][0]:   #..may or may not include them anyway.
        cf.fields[i].hdr = cols[1]

proc hdrWrite(cf: var DpCf, diff=false) =
  proc sgn(x: int): int = (if x < 0: -1 else: +1)   #export or re-locate?
  for i, f in cf.fields:
    if f.prefix.len > 0: stdout.write f.prefix  #.wid += f.prefix.printedLen?
    if diff and f.c in cf.diffCmp and cf.attrDiff.len > 0:
      stdout.write cf.attrDiff
    cf.fields[i].wid  = f.wid.sgn * max(f.wid.abs, f.hdr.printedLen)
    if   cf.fields[i].wid > 0: stdout.write alignLeft(f.hdr, cf.fields[i].wid)
    elif cf.fields[i].wid < 0: stdout.write f.hdr
    if diff and f.c in cf.diffCmp and cf.attrDiff.len > 0:
      stdout.write cf.a0
  stdout.write '\n'

# Tricky/slow to avoid zero visible width columns under common-case space split.
proc fmtWrite(cf: var DpCf, p: var Proc, delta=0) =
  p.ageD = if delta == 0: cf.uptm - p.t0 else: delta.culong
  var used = 0
  let ats = p.kattr
  for i, f in cf.fields:
    var fld: string
    let pfx  = f.prefix 
    let nPfx = pfx.printedLen
    if f.wid < 0:               # Only clip at end of line
      let fp = f.fmt(p, max(1, cf.width - used - nPfx))
      let bod = fp.findNot Whitespace
      fld = if bod >= 0: pfx & fp[0 ..< bod] & ats & fp[bod..^1] & ats
            else       : pfx & fp & ats
    else:
      let fp  = f.fmt(p)
      let nfp = fp.printedLen
      let bod = fp.findNot Whitespace
      let fpr = if bod >= 0: fp[0 ..< bod] & ats & fp[bod..^1] & ats
                else       : ats & fp & ats     # fp reconstituted
      if nfp > f.wid:           # Over-wide instance; Let it mess up alignments
        fld = pfx & fpr
        cf.fields[i].wid = nfp  # Track max so only future can sorta align
      else:                     # Left or Right aligned
        let pad = repeat(' ', f.wid - nfp)
        fld = if f.left: pfx & fpr & pad
              else     : pfx & pad & fpr
    stdout.write fld
    if i != cf.fields.len - 1:
      used += printedLen(fld)
  stdout.write cf.a0, '\n'

proc setRealIDs*(cf: var DpCf; realIds=false) =
  ##Change DpCf&global data (cmpOf,fmtOf) to use /proc/PID/status real uid/gid.
  if realIds:       #/proc/PID/status is very slow; Any other reliable source?
    cf.uidNeeds = {pfs_uids}; cf.gidNeeds = {pfs_gids}
    cf.usrNeeds = {pfs_usrs}; cf.grpNeeds = {pfs_grps}
  else:
    cf.uidNeeds = {pffs_uid}; cf.gidNeeds = {pffs_gid}
    cf.usrNeeds = {pffs_usr}; cf.grpNeeds = {pffs_grp}
  cmpOf['u'].pfs = cf.uidNeeds; cmpOf['z'].pfs = cf.gidNeeds
  cmpOf['U'].pfs = cf.usrNeeds; cmpOf['Z'].pfs = cf.grpNeeds
  fmtOf['u'].pfs = cf.uidNeeds; fmtOf['z'].pfs = cf.gidNeeds
  fmtOf['U'].pfs = cf.usrNeeds; fmtOf['Z'].pfs = cf.grpNeeds

const ts0 = Timespec(tv_sec: 0.Time, tv_nsec: 0.int)
proc fin*(cf: var DpCf, entry=Timespec(tv_sec: 0.Time, tv_nsec: 9.clong)) =
  ##Finalize cf ob post-user sets/updates, pre-``display`` calls.  Proc ages are
  ##times relative to ``entry``.  Non-default => time of ``fin`` call.
  cf.setRealIDs(cf.realIds)     #important to do this before any compilers run
  cf.a0 = if cf.plain: "" else: textAttrOff
  cf.needKin = not cf.plain
  if cf.width == 0: cf.width = terminalWidth()
  if cf.delay >= ts0 and cf.diffCmp.len==0: cf.diffCmp = "J"  #default to cumCPU
  cf.tests = builtin                              #Initially populate w/builtin
  cf.parseKind                                    #.kind to tests additions
  cf.colors.textAttrRegisterAliases               #.colors => registered aliases
  cf.parseColor                                   #.color => .attr
  cf.parseFilters                                 #(in|ex)cl => sets s(in|ex)
  cf.needUptm = cf.order.parseOrder(cf.cmps, cf.need)   #.order => .cmps
  cf.needUptm = cf.needUptm or cf.diffCmp.parseOrder(cf.diffCmps, cf.diff)
  cf.need = cf.need + cf.diff
  cf.parseAge                                     #.ageFmt => .tmFmt
  cf.parseFormat                                  #.format => .fields
  cf.parseMerge                                   #.merge => .mergeKDs
  cf.parseHdrs                                    #.hdrs => fixed up .fields.hdr
  if cf.forest: cf.need = cf.need + {pf_pid0, pf_ppid0}
  cf.sneed = needs(cf.need)                       #inits usrs&grps if necessary
  cf.uAbb = parseAbbrev(cf.maxUnm); cf.uAbb.realize(usrs)
  cf.gAbb = parseAbbrev(cf.maxGnm); cf.gAbb.realize(grps)
  cf.t0 = if entry.tv_sec.clong==0 and entry.tv_nsec==9: getTime() else: entry
  if cf.needUptm: cf.uptm = procUptime()          #uptime in seconds
  if cf.needTotRAM: cf.totRAM = procMemInfo().MemTotal
  cg = cf.addr                                    #Init global ptr
  cmpsG = cf.cmps.addr                            #Init global ptr

proc pidPath(parent: Table[Pid, Pid], pid: Pid): seq[Pid] =
  var pid = pid
  result.add pid
  while (pid := parent.getOrDefault(pid)) != 0:
    result.add pid
  result.reverse
  if result[0] == 2: result[0] = 0  #So kernel threads come first

#XXX display,displayASAP should grow a threads mode like '/bin/ps H' etc.
#XXX display,displayASAP should grow --action so caller can use user-defd kinds.
proc displayASAP*(cf: var DpCf) =
  ## Aggressively output as we go; Incompatible with non-kernel-default sorts.
  ## This yields much faster initial/gradual output on a struggling system.
  if cf.header: cf.hdrWrite
  var last = initTable[Pid, Proc](4)
  var p: Proc
  let it = pidsIt(cf.pids)
  for pid in it():
    if p.read(pid, cf.need, cf.sneed) and not cf.failsFilters(p):
      cf.fmtWrite p, 0    #Flush lowers user-perceived latency by up to 100x at
      stdout.flushFile    #..a cost < O(5%): well worth it whenever it matters.
      if cf.delay >= ts0: last[p.pid] = p
#XXX Sort NEEDS all procs@once; COULD print non-merged/min depth ASAP; rest@end.
  if cf.delay < ts0: return
  let dJiffies = cf.delay.tv_sec.int * 100 + (cf.delay.tv_nsec.int div 100)
  cmpsG = cf.diffCmps.addr
  var zero: Proc
  var next = initTable[Pid, Proc](4)
  while true:
    nanosleep(cf.delay)
    if cf.needUptm: cf.uptm = procUptime()  #XXX getTime() is surely faster
    next.clear
    stdout.write '\n'
    if cf.header: cf.hdrWrite true
    let it = pidsIt(cf.pids)
    for pid in it():
      if p.read(pid, cf.need, cf.sneed) and not cf.failsFilters(p):
        next[p.pid] = p
        p.minusEq(last.getOrDefault(p.pid), cf.diff)
        if multiLevelCmp(p.addr, zero.addr) != 0:
          cf.fmtWrite p, dJiffies
          stdout.flushFile
    last = next

proc maybeMerge(cf: var DpCf, procs2: var seq[Proc], p: Proc, need: ProcFields,
                lastSlot: var Table[tuple[k, d: uint8], int]): bool =
  for d, k in p.kind:
    let kd = (k, d.uint8)
    if kd in cf.mergeKDs:
      try:
        procs2[lastSlot[kd]].merge p, need
      except KeyError:
        lastSlot[kd] = procs2.len
        procs2.add p
        procs2[^1].cmd = cf.kslotNm[k] & "/"
        procs2[^1].cmdLine = procs2[^1].cmd
      return true

proc display*(cf: var DpCf) = # [AMOVWYbkl] free
  ##Display running processes `pids` (all passing filter if empty) in a tabular,
  ##colorful, maybe sorted way.  Cmd params/cfg files are very similar to `lc`.
  ##
  ##For MULTI-LEVEL order specs only +- mean incr(dfl)/decreasing. The following
  ##1-letter codes work for BOTH format AND order specs:
  ##  p PID      z GID   w WCHAN  j TIME  L FLG  f MNFL  o SID    Q SIGQ
  ##  c CMD      Z GRP   s STAT   J CTIM  v VSZ  F MJFL  G TPGID  q PENDING
  ##  C COMMAND  P PPID  t TTY    e %cPU  d DRS  h CMNF  K STACK  X SHDPND
  ##  u UID      n NI    a AGE    E %CPU  r TRS  H CMJF  S ESP    B BLOCKED
  ##  U USER     y PRI   T START  m %MEM  R RSS  g PGID  I EIP    i IGNORED
  ##  D fmt:depth-in-tree; order:pid-path; BOTH=>forest-indent    x CAUGHT
  ##  0-6 string values of /proc/PID/fd/0-6 symlinks     O oomSco
  ##
  ##ATTR specs: NONE, plain, bold, italic, underline, blink, inverse, struck,
  ##black,red,green,yellow,blue,purple,cyan,white; UPPERCASE=>HIGHintensity;
  ##"on_" prefix => BACKGROUND color; 256-color xterm attrs: [fb][0..23] for
  ##FORE/BACKgrnd grey scale&[fb]RGB a 6x6x6 color cube; each [RGB] is on [0,5].
  ##xterm/st true colors are [fb]HHHHHH (common R,G,B hex).  Field AND strftime
  ##formats both accept %{ATTR1 ATTR2..}CODE to set colors for any %CODE field.
  if cf.cmps.len == 0 and cf.merge.len == 0 and not cf.forest:
    cf.displayASAP(); return
  if cf.header: cf.hdrWrite
  var last = initTable[Pid, Proc](4)
  var parent = initTable[Pid, Pid]()
  var procs = newSeqOfCap[Proc](cf.pids.len)
  let it = pidsIt(cf.pids)
  for pid in it():
    procs.setLen procs.len + 1
    if not procs[^1].read(pid, cf.need, cf.sneed) or cf.failsFilters(procs[^1]):
      zeroMem procs[^1].addr, Proc.sizeof; procs.setLen procs.len - 1
      continue
    if cf.forest: parent[procs[^1].pid0] = procs[^1].ppid0
  if cf.forest:
    for i in 0 ..< procs.len: procs[i].pidPath = parent.pidPath(procs[i].pid0)
  if cf.merge.len > 0:
    var procs2: seq[Proc]
    var lastSlot = initTable[tuple[k,d:uint8], int](procs.len)
    for p in procs:
      if not cf.maybeMerge(procs2, p, cf.need, lastSlot): procs2.add p
    procs = procs2
  if cf.delay >= ts0:
    for p in procs: last[p.pid] = p
  if cf.cmps.len > 0:
    var ptrs = newSeq[ptr Proc](procs.len)
    for i in 0 ..< procs.len: ptrs[i] = procs[i].addr
    ptrs.sort(multiLevelCmp)
    for pp in ptrs: cf.fmtWrite pp[], 0
  else:
    for p in procs: cf.fmtWrite p.unsafeAddr[], 0
  if cf.delay < ts0: return
  let dJiffies = cf.delay.tv_sec.int * 100 + (cf.delay.tv_nsec.int div 100)
  var zero: Proc
  var next = initTable[Pid, Proc](4)
  while true:
    stdout.flushFile
    nanosleep(cf.delay)
    if cf.needUptm: cf.uptm = procUptime()  #XXX getTime() is surely faster
    next.clear; procs.setLen 0; parent.clear
    stdout.write '\n'
    if cf.header: cf.hdrWrite true
    cmpsG = cf.diffCmps.addr
    let it = pidsIt(cf.pids)
    for pid in it():
      procs.setLen procs.len + 1
      if not procs[^1].read(pid,cf.need,cf.sneed) or cf.failsFilters(procs[^1]):
        zeroMem procs[^1].addr, Proc.sizeof
        procs.setLen procs.len - 1
        continue
      next[procs[^1].pid] = procs[^1]
      procs[^1].minusEq(last.getOrDefault(procs[^1].pid), cf.diff)
      if multiLevelCmp(procs[^1].addr, zero.addr) == 0:
        zeroMem procs[^1].addr, Proc.sizeof; procs.setLen procs.len - 1
        continue
    if cf.merge.len > 0:
      var procs2: seq[Proc]
      var lastSlot=initTable[tuple[k,d:uint8], int](procs.len)
      for p in procs:
        if not cf.maybeMerge(procs2, p, cf.need, lastSlot): procs2.add p
      procs = procs2
    if cf.cmps.len > 0:
      var ptrs = newSeq[ptr Proc](procs.len)
      for i in 0 ..< procs.len: ptrs[i] = procs[i].addr
      cmpsG = cf.cmps.addr
      ptrs.sort(multiLevelCmp)
      for pp in ptrs: cf.fmtWrite pp[], dJiffies
    else:
      for p in procs: cf.fmtWrite p.unsafeAddr[], dJiffies
    last = next

# # # # # # # COMMAND-LINE INTERFACE: find # # # # # # #
#Redundant upon `display` with some non-display action, but its simpler filter
#language (syntax&impl) can be much more efficient (for user&system) sometimes.
proc contains(rxes: seq[Regex], p: Proc, full=false): bool =
  let c = if full and p.cmdLine.len > 0: p.cmdLine.cmdClean else: p.cmd
  for r in rxes:  #Needs to be
    if c.contains(r): return true

proc nsNotEq(p, q: Proc, nsList: seq[NmSpc]): bool =
  result = true
  for n in nsList:
    case n
    of nsIpc:      (if q.nIpc      != p.nIpc     : return false)
    of nsMnt:      (if q.nMnt      != p.nMnt     : return false)
    of nsNet:      (if q.nNet      != p.nNet     : return false)
    of nsPid:      (if q.nPid      != p.nPid     : return false)
    of nsUser:     (if q.nUser     != p.nUser    : return false)
    of nsUts:      (if q.nUts      != p.nUts     : return false)
    of nsCgroup:   (if q.nCgroup   != p.nCgroup  : return false)
    of nsPid4Kids: (if q.nPid4Kids != p.nPid4Kids: return false)

proc act(actions: seq[PdAct], pid: Pid, delim: string, sigs: seq[cint],
         nice: int, cnt: var int, nErr: var int) =
  for a in actions:
    case a
    of acEcho : stdout.write pid, delim
    of acKill : nErr += (kill(pid, sigs[0]) == -1).int
    of acNice : nErr += (nice(pid, nice.cint) == -1).int
    of acWait1: discard
    of acWaitA: discard
    of acCount: cnt.inc

let signum* = { #suppress archaic STKFLT so "ST" can imply STOP; alias CLD,SYS
  "HUP" :  1, "INT" :  2, "QUIT"  :  3, "ILL"   :  4, "TRAP" :  5, "ABRT":  6,
  "BUS" :  7, "FPE" :  8, "KILL"  :  9, "USR1"  : 10, "SEGV" : 11, "USR2": 12,
  "PIPE": 13, "ALRM": 14, "TERM"  : 15, "stkflt": 16, "CHLD" : 17, "CLD" : 17,
  "CONT": 18, "STOP": 19, "TSTP"  : 20, "TTIN"  : 21, "TTOU" : 22, "URG" : 23,
  "XCPU": 24, "XFSZ": 25, "VTALRM": 26, "PROF"  : 27, "WINCH": 28, "POLL": 29,
  "PWR" : 30, "SYS" : 31, "UNUSED": 31 }.toCritBitTree

proc ctrlC() {.noconv.} = echo ""; quit 130
setControlCHook(ctrlC)
proc find*(pids="", full=false, ignoreCase=false, parent: seq[Pid] = @[],
    pgroup: seq[Pid] = @[], session: seq[Pid] = @[], tty: seq[string] = @[],
    group: seq[string] = @[], euid: seq[string] = @[], uid: seq[string] = @[],
    root=0.Pid, ns=0.Pid, nsList: seq[NmSpc] = @[], first=false, newest=false,
    oldest=false, exclude: seq[string] = @[], invert=false,
    delay=Timespec(tv_sec: 0.Time, tv_nsec: 40_000_000.int), delim="\n",
    signals: seq[string] = @[], nice=0, actions: seq[PdAct] = @[],
    PCREpatterns: seq[string]): int =
  ## Find subset of procs by various criteria & act upon them ASAP (echo, count,
  ## kill, nice, wait for any|all).  Unifies pidof, pgrep, pkill, snice, waita
  ## features in one command with options most similar to pgrep.
  let pids: seq[string] = if pids.len > 0: pids.splitWhitespace else: @[ ]
  var actions = (if actions.len == 0: @[acEcho] else: actions)
  let exclPPID = "PPID" in exclude
  let selfPgrp = if exclPPID: getpgid(0) else: 0
  var exclPIDs = initHashSet[string](min(1, exclude.len))
  for p in exclude: exclPIDs.incl (if p == "PPID": $getppid() else: p)
  exclPIDs.incl $getpid()               #always exclude self
  var pList: seq[Pid]
  var fill: ProcFields                  #field needs
  var rxes: seq[Regex]
  var sigs: seq[cint]
  var p, q: Proc
  for sig in signals:
    if sig.len > 0 and sig[0] in { '0' .. '9' }: sigs.add toCin(sig)
    else: sigs.add signum.match(sig.toUpper, "signal name").val.cint
  if nice != 0 and acNice notin actions: actions.add acNice
  if sigs.len > 0 and acKill notin actions: actions.add acKill
  if sigs.len == 0 and acKill in actions: sigs.add 15 #default to SIGTERM=15
  if PCREpatterns.len > 0:
    fill.incl pf_cmd
    if full: fill.incl pfcl_cmdline
  else:
    if pids.len==0 and parent.len==0 and pgroup.len==0 and session.len==0 and
       tty.len==0 and group.len==0 and euid.len==0 and uid.len==0 and
       root==0 and ns==0:
      stderr.write "procs: no criteria given; -h for help; exiting\n"
      return 1
  if ignoreCase:        #compile patterns
    for pattern in PCREpatterns: rxes.add re("(?i)" & pattern)
  else:
    for pattern in PCREpatterns: rxes.add pattern.re
  let tty  = ttyToDev(tty) ; let group = grpToGid(group)  #name|nums->nums
  let euid = usrToUid(euid); let uid   = usrToUid(uid)
  if parent.len  > 0: fill.incl pf_ppid0
  if pgroup.len  > 0: fill.incl pf_pgrp
  if session.len > 0: fill.incl pf_sess
  if tty.len     > 0: fill.incl pf_tty
  if group.len   > 0: fill.incl pffs_gid
  if euid.len    > 0: fill.incl pffs_uid
  if uid.len     > 0: fill.incl pfs_uids
  if root != 0      : fill.incl pfr_root
  if ns != 0:
    for ns in nsList: fill.incl toPfn(ns)
  if newest or oldest: fill.incl pf_t0
  let sneed = needs(fill)               #source needs
  discard q.read($ns, fill, sneed)      #XXX pay attn to errors? Eg. non-root
  if root!=0 and root!=ns: q.root=readlink("/proc/" & $root & "/root", devNull)
  let root = if q.root == "": 0 else: root          #ref root unreadable=>cancel
  let it = pidsIt(pids)
  let workAtEnd = sigs.len > 1 or acWait1 in actions or acWaitA in actions
  var tM = if newest: 0.uint else: 0x0FFFFFFFFFFFFFFF.uint  #running min/max t0
  var cnt = 0; var t0: Timespec
  for pid in it():
    if pid in exclPIDs: continue                    #skip specifically excluded
    if not p.read(pid, fill, sneed): continue       #proc gone or perm problem
    var match = 1
    if   newest and p.t0.uint < tM                    : match = 0
    elif oldest and p.t0.uint > tM                    : match = 0
    elif parent.len  > 0 and p.ppid0     notin parent : match = 0
    elif pgroup.len  > 0 and p.pgrp      notin pgroup : match = 0
    elif exclPPID        and p.pgrp != selfPgrp       : match = 0
    elif session.len > 0 and p.sess      notin session: match = 0
    elif tty.len     > 0 and p.tty       notin tty    : match = 0
    elif group.len   > 0 and p.st.st_gid notin group  : match = 0
    elif euid.len    > 0 and p.st.st_uid notin euid   : match = 0
    elif uid.len     > 0 and p.uids[0]   notin uid    : match = 0
    elif ns != 0         and p.nsNotEq(q, nsList)     : match = 0
    elif root != 0       and p.root != q.root         : match = 0
    elif rxes.len    > 0 and not rxes.contains(p,full): match = 0
    if (match xor invert.int) == 0: continue  #-v messes up newest/oldest logic
    if (newest or oldest) and pList.len == 0: #first passing always new min|max
        tM = p.t0; pList.add p.pid; continue
    if newest:                                #t0 < tM has already been skipped
      if p.t0 == tM and p.pid > pList[0]:     #PIDs wrap around=>iffy tie-break
        tM = p.t0; pList.setLen 1; pList[0] = p.pid   #update max
      continue
    elif oldest:                              #t0 > tM has already been skipped
      if p.t0 == tM and p.pid < pList[0]:     #PIDs wrap around=>iffy tie-break
        tM = p.t0; pList.setLen 1; pList[0] = p.pid   #update min
      continue
    actions.act(p.pid, delim, sigs, nice, cnt, result)
    if acKill in actions and sigs.len > 1 and delay > ts0:
      t0 = getTime()
    if workAtEnd: pList.add p.pid
    if first: break               #first,newest,oldest are mutually incompatible
  if newest or oldest and pList.len > 0:
    actions.act(pList[0], delim, sigs, nice, cnt, result)
  if acCount in actions:
    stderr.write cnt, "\n"
  if acKill in actions and sigs.len > 1:      #send any remaining signals
    var dt = delay - (getTime() - t0)
    if dt < delay: dt.nanosleep
    for i, sig in sigs[1..^1]:
      for pid in pList: result += (kill(pid, sig) == -1).int
      if i < sigs.len - 2: delay.nanosleep
  if pList.len > 0:                           #wait for condition if requested
    if   acWait1 in actions: discard waitAny(pList, delay)
    elif acWaitA in actions: waitAll(pList, delay)

# # # # COMMAND-LINE INTERFACE: scrollSys - system-wide scrolling stats # # # #
type
  ScField = tuple[ss: SysSrcs; wid: int; hdr: string;
                  fmt: proc(dtI: float; w: int; last,curr: Sys): string]
  ScCf* = object
    colors*, color*: seq[string]                            ##usrDefd colors
    hdrs*: seq[string]                                      ##usrDefd headers
    frqHdr*, numIt*: int                                    ##header frq, itrs
    delay*: Timespec                                        ##delay between itrs
    binary*, plain*, unnorm*: bool                          ##flags; see help
    disks*, ifaces*, format*: seq[string]                   ##fmts to display
    fields: seq[ScField]                                    #fields to format
    cpuNorm: float
    dks, ifs: seq[Regex]                                    #devs to total
    headers: string                                         #selected headers
    loadFmts: seq[tuple[level: uint; attr: string]]
    need: SysSrcs
    a0: string                                              #if plain: ""
    attrSize: array[0..25, string]  #CAP letter-indexed with ord(x) - ord('A')

var cs: ptr ScCf            #Lazy way out of making many little procs take ScCf

proc fmtLoad(n: uint): string =
  result = cs.loadFmts[^1].attr
  for (lvl, fmt) in cs.loadFmts:
    if lvl >= n: return fmt

proc fmtJ(n: uint; wid: int): string =
  fmtLoad(n) & align(humanReadable4(n.uint, cs.binary), wid) & cs.a0

proc fmtLoadAvg(s: string; wid: int): string =
  let s = align(s, wid) #take '.' out of load, parse into int, feed to fmtLoad.
  let jiffieEquivalent = (parseInt(join(s.split('.')).strip()).float *
                          cs.cpuNorm).uint
  if cs.plain: s else: fmtLoad(jiffieEquivalent) & s & cs.a0

proc fmtZ(b: uint, wid: int): string = fmtSz(cs.attrSize,cs.a0,cs.binary,b,wid)

var sysFmt: Table[string, ScField]
template sAdd(code, sfs, wid, hdr, toStr: untyped) {.dirty.} =
  sysFmt[code] = (sfs, wid, hdr,
                  proc(dtI: float; w: int; last,curr: Sys): string {.closure.} =
                    toStr)
sAdd("btm", {ssStat},     10, "bootTmSec"): align($curr.s.bootTime, w)
sAdd("prn", {ssStat},      3, "PRn"      ): align($curr.s.procsRunnable, w)
sAdd("pbl", {ssStat},      3, "PBl"      ): align($curr.s.procsBlocked, w)
sAdd("la1", {ssLoadAvg},   5, "LdAv1"    ): fmtLoadAvg(curr.l.m1, w)
sAdd("la5", {ssLoadAvg},   5, "LdAv5"    ): fmtLoadAvg(curr.l.m5, w)
sAdd("la15",{ssLoadAvg},   5, "LdAv15"   ): fmtLoadAvg(curr.l.m15, w)
sAdd("mtot",{ssMemInfo},   4, "mTot"     ): fmtZ(curr.m.MemTotal      , w)
sAdd("mfre",{ssMemInfo},   4, "mFre"     ): fmtZ(curr.m.MemFree       , w)
sAdd("mavl",{ssMemInfo},   4, "mAvl"     ): fmtZ(curr.m.MemAvailable  , w)
sAdd("mbuf",{ssMemInfo},   4, "mBuf"     ): fmtZ(curr.m.Buffers       , w)
sAdd("mchd",{ssMemInfo},   4, "mChd"     ): fmtZ(curr.m.Cached        , w)
sAdd("mswc",{ssMemInfo},   4, "mSwC"     ): fmtZ(curr.m.SwapCached    , w)
sAdd("mact",{ssMemInfo},   4, "mAct"     ): fmtZ(curr.m.Active        , w)
sAdd("miac",{ssMemInfo},   4, "mIAc"     ): fmtZ(curr.m.Inactive      , w)
sAdd("maca",{ssMemInfo},   4, "mAcA"     ): fmtZ(curr.m.ActiveAnon    , w)
sAdd("miaa",{ssMemInfo},   4, "mIAA"     ): fmtZ(curr.m.InactiveAnon  , w)
sAdd("maf" ,{ssMemInfo},   4, "mAF"      ): fmtZ(curr.m.ActiveFile    , w)
sAdd("miaf",{ssMemInfo},   4, "mIAF"     ): fmtZ(curr.m.InactiveFile  , w)
sAdd("mune",{ssMemInfo},   4, "mUne"     ): fmtZ(curr.m.Unevictable   , w)
sAdd("mlck",{ssMemInfo},   4, "mLck"     ): fmtZ(curr.m.Mlocked       , w)
sAdd("mswt",{ssMemInfo},   4, "mSwT"     ): fmtZ(curr.m.SwapTotal     , w)
sAdd("mswf",{ssMemInfo},   4, "mSwF"     ): fmtZ(curr.m.SwapFree      , w)
sAdd("mdty",{ssMemInfo},   4, "mDty"     ): fmtZ(curr.m.Dirty         , w)
sAdd("mwb" ,{ssMemInfo},   4, "mWB"      ): fmtZ(curr.m.Writeback     , w)
sAdd("manp",{ssMemInfo},   4, "mAnP"     ): fmtZ(curr.m.AnonPages     , w)
sAdd("mmap",{ssMemInfo},   4, "mMap"     ): fmtZ(curr.m.Mapped        , w)
sAdd("mshm",{ssMemInfo},   4, "mShm"     ): fmtZ(curr.m.Shmem         , w)
sAdd("mkrc",{ssMemInfo},   4, "mKRc"     ): fmtZ(curr.m.KReclaimable  , w)
sAdd("mslb",{ssMemInfo},   4, "mSlb"     ): fmtZ(curr.m.Slab          , w)
sAdd("msrc",{ssMemInfo},   4, "mSRc"     ): fmtZ(curr.m.SReclaimable  , w)
sAdd("murc",{ssMemInfo},   4, "mURc"     ): fmtZ(curr.m.SUnreclaim    , w)
sAdd("mkst",{ssMemInfo},   4, "mKSt"     ): fmtZ(curr.m.KernelStack   , w)
sAdd("mptb",{ssMemInfo},   4, "mPTb"     ): fmtZ(curr.m.PageTables    , w)
sAdd("mnfs",{ssMemInfo},   4, "mNFS"     ): fmtZ(curr.m.NFS_Unstable  , w)
sAdd("mbnc",{ssMemInfo},   4, "mBnc"     ): fmtZ(curr.m.Bounce        , w)
sAdd("mwbt",{ssMemInfo},   4, "mWBT"     ): fmtZ(curr.m.WritebackTmp  , w)
sAdd("mclm",{ssMemInfo},   4, "mCLm"     ): fmtZ(curr.m.CommitLimit   , w)
sAdd("mcas",{ssMemInfo},   4, "mCAS"     ): fmtZ(curr.m.Committed_AS  , w)
sAdd("mvmt",{ssMemInfo},   4, "mVMt"     ): fmtZ(curr.m.VmallocTotal  , w)
sAdd("mvmu",{ssMemInfo},   4, "mVMu"     ): fmtZ(curr.m.VmallocUsed   , w)
sAdd("mvmc",{ssMemInfo},   4, "mVMc"     ): fmtZ(curr.m.VmallocChunk  , w)
sAdd("mpcp",{ssMemInfo},   4, "mpcp"     ): fmtZ(curr.m.Percpu        , w)
sAdd("mahp",{ssMemInfo},   4, "mAHP"     ): fmtZ(curr.m.AnonHugePages , w)
sAdd("mshp",{ssMemInfo},   4, "mSHP"     ): fmtZ(curr.m.ShmemHugePages, w)
sAdd("mspm",{ssMemInfo},   4, "mSPM"     ): fmtZ(curr.m.ShmemPmdMapped, w)
sAdd("mcmt",{ssMemInfo},   4, "mcmt"     ): fmtZ(curr.m.CmaTotal      , w)
sAdd("mcmf",{ssMemInfo},   4, "mcmf"     ): fmtZ(curr.m.CmaFree       , w)
sAdd("mhpt",{ssMemInfo},   4, "mHPt"     ): fmtZ(curr.m.HugePagesTotal, w)
sAdd("mhpf",{ssMemInfo},   4, "mHPf"     ): fmtZ(curr.m.HugePagesFree , w)
sAdd("mhpr",{ssMemInfo},   4, "mHPr"     ): fmtZ(curr.m.HugePagesRsvd , w)
sAdd("mhps",{ssMemInfo},   4, "mHPs"     ): fmtZ(curr.m.HugePagesSurp , w)
sAdd("mhpz",{ssMemInfo},   4, "mHPz"     ): fmtZ(curr.m.Hugepagesize  , w)
sAdd("mhpb",{ssMemInfo},   4, "mHPb"     ): fmtZ(curr.m.Hugetlb       , w)
sAdd("mdmk",{ssMemInfo},   4, "mdmK"     ): fmtZ(curr.m.DirectMap4k   , w)
sAdd("mdmm",{ssMemInfo},   4, "mdmM"     ): fmtZ(curr.m.DirectMap2M   , w)
sAdd("mdmg",{ssMemInfo},   4, "mdmG"     ): fmtZ(curr.m.DirectMap1G   , w)

template dAdd(code, sfs, wid, hdr, toStr, getNum: untyped) {.dirty.} =
  sysFmt[code] = (sfs, wid, hdr,
                  proc(dtI: float; w: int; last,curr: Sys):string {.closure.}=
                    proc get(sys: Sys): int = with(sys, [ m, s, d, n ], getNum)
                    let nrm = if toStr == fmtJ: cs.cpuNorm else: 1.0
                    toStr((nrm*(curr.get - last.get).float * dtI + 0.5).uint,w))

template cpuOrZero(c: seq[CPUInfo], i: int, fld): int =
  if c.len == 0: 0 else: c[i].fld       #First sample has s.cpu.len == 0
dAdd("usrj", {ssStat},    4, "UsrJ", fmtJ): cpuOrZero(s.cpu, 0, user)
dAdd("nicj", {ssStat},    4, "NicJ", fmtJ): cpuOrZero(s.cpu, 0, nice)
dAdd("sysj", {ssStat},    4, "SysJ", fmtJ): cpuOrZero(s.cpu, 0, system)
dAdd("idlj", {ssStat},    4, "IdlJ", fmtJ): cpuOrZero(s.cpu, 0, idle)
dAdd("iowj", {ssStat},    4, "IOWJ", fmtJ): cpuOrZero(s.cpu, 0, iowait)
dAdd("hirj", {ssStat},    4, "HIrJ", fmtJ): cpuOrZero(s.cpu, 0, irq)
dAdd("sirj", {ssStat},    4, "SIrJ", fmtJ): cpuOrZero(s.cpu, 0, softirq)
dAdd("stlj", {ssStat},    4, "StlJ", fmtJ): cpuOrZero(s.cpu, 0, steal)
dAdd("gstj", {ssStat},    4, "GstJ", fmtJ): cpuOrZero(s.cpu, 0, guest)
dAdd("gncj", {ssStat},    4, "GNcJ", fmtJ): cpuOrZero(s.cpu, 0, guest_nice)
#XXX Some uses (iostat) want local rather than global name sets; Eg "drb:sda".
#XXX Also, above specified CPUs e.g. usr:<N>.  With params, we need >= 1 more
#XXX hdr rows containing used parameter.  May also want filter by maj/min devNo.
#XXX softIRQ; probably rest of interrupts as well. (Also needs params...)

dAdd("intr", {ssStat},    4, "Intr", fmtZ): s.interrupts
dAdd("ctsw", {ssStat},    4, "CtSw", fmtZ): s.contextSwitches
dAdd("pmad", {ssStat},    4, "PMad", fmtZ): s.procs

proc matchAny*(s: string, rxes: seq[Regex]): bool =
  ## Return ``true`` iff ``s`` matches one of ``rxes`` *or* if ``rxes.len==0``.
  if rxes.len == 0: return true
  for r in rxes:
    if s.contains(r): return true

template filteredSum(sts: DiskStats|NetDevStats, rxes: seq[Regex]): int =
  var sum = 0                   #May be worth saving result in ScCf someday
  for st in sts:
    if st.name.matchAny(rxes):  #For disks, maj,min devNo matching would be
      sum += st.get             #..more efficient, but sts.len =~ few dozen.
  sum

template tot(d: DiskStats, dks: seq[Regex], getNum: untyped): int =
  proc get(ds: DiskStat): int = with(ds, [reads, writes, cancels,
                                          inFlight, ioTicks, timeInQ], getNum)
  filteredSum(d, dks)
dAdd("dbrd", {ssDiskStat}, 4, "DBRd", fmtZ): d.tot(cs.dks, reads.nSector)*512
dAdd("dbwr", {ssDiskStat}, 4, "DBWr", fmtZ): d.tot(cs.dks, writes.nSector)*512
dAdd("dbcn", {ssDiskStat}, 4, "DBCn", fmtZ): d.tot(cs.dks, cancels.nSector)*512
dAdd("dnrd", {ssDiskStat}, 4, "D#Rd", fmtZ): d.tot(cs.dks, reads.nIO)
dAdd("dnwr", {ssDiskStat}, 4, "D#Wr", fmtZ): d.tot(cs.dks, writes.nIO)
dAdd("dncn", {ssDiskStat}, 4, "D#Cn", fmtZ): d.tot(cs.dks, cancels.nIO)
dAdd("difl", {ssDiskStat}, 4, "DiFl", fmtZ): d.tot(cs.dks, inFlight)
dAdd("ditk", {ssDiskStat}, 4, "DITk", fmtZ): d.tot(cs.dks, ioTicks )
dAdd("dtiq", {ssDiskStat}, 4, "DTiQ", fmtZ): d.tot(cs.dks, timeInQ )

template tot(n: NetDevStats, ifs: seq[Regex], getNum: untyped): int =
  proc get(nd: NetDevStat): int = with(nd, [rcvd, sent], getNum)
  filteredSum(n, ifs)
dAdd("nbrc", {ssNetDev},   4, "NBR", fmtZ): n.tot(cs.ifs, rcvd.bytes)
dAdd("nbsn", {ssNetDev},   4, "NBS", fmtZ): n.tot(cs.ifs, sent.bytes)
dAdd("nprc", {ssNetDev},   4, "N#R", fmtZ): n.tot(cs.ifs, rcvd.packets)
dAdd("npsn", {ssNetDev},   4, "N#S", fmtZ): n.tot(cs.ifs, sent.packets)

proc parseFormat(cf: var ScCf) =
  let format = if cf.format.len > 0: cf.format else:
                 @[ "usrj","sysj","iowj","hirj","sirj", "pmad","la1", "mavl",
                    "intr","ctsw", "dnrd","dnwr", "dbrd","dbwr", "nbrc","nbsn" ]
  var hdrMap: Table[string, string]
  var hdr: string
  for h in cf.hdrs:
    let cols = h.split(':')
    if cols.len != 2: raise newException(ValueError, "Bad hdrs: \"" & h & "\"")
    hdrMap[cols[0]] = cols[1]
  cf.fields.setLen(0)
  for i, f in format:
    try   : cf.fields.add sysFmt[f]
    except: raise newException(ValueError, "unknown format code \"" & f & "\"")
    try   : hdr = hdrMap[cf.fields[^1].hdr]
    except KeyError: hdr = cf.fields[^1].hdr
    cf.fields[^1].wid = max(cf.fields[^1].wid, hdr.len)
    if i != 0: cf.headers.add ' '
    cf.headers.add align(hdr, cf.fields[^1].wid)
    cf.need = cf.need + cf.fields[^1].ss
  cf.headers.add '\n'

proc parseColor(cf: var ScCf) =
  for spec in cf.color:
    let cols = spec.splitWhitespace()
    if cols.len < 2:
      raise newException(ValueError, "bad color format: \"" & spec & "\"")
    let nm = cols[0]
    if nm.startsWith("size") and nm.len == 5:
      if nm[4] in { 'B', 'K', 'M', 'G', 'T' }:
        cf.attrSize[ord(nm[4]) - ord('A')] = textAttrOn(cols[1..^1], cf.plain)
      else: raise newException(ValueError, "bad color metric: \"" & spec & "\"")
    elif nm.startsWith("load") and nm.len > 4:
      var level: int
      if parseInt(nm, level, 4) > 0:
        cf.loadFmts.add (level.uint, textAttrOn(cols[1..^1], cf.plain))
      else: raise newException(ValueError, "bad color metric: \"" & spec & "\"")
    else: raise newException(ValueError, "bad color name: \"" & spec & "\"")

proc fin*(cf: var ScCf) =
  ##Finalize cf ob post-user sets/updates, pre-``scrollSys`` calls.
  cf.a0 = if cf.plain: "" else: textAttrOff
  if cf.numIt == -1: cf.numIt = cf.numIt.typeof.high
  cf.colors.textAttrRegisterAliases               #.colors => registered aliases
  for d in cf.disks: cf.dks.add d.re
  for i in cf.ifaces: cf.ifs.add i.re
  cf.cpuNorm = if cf.unnorm: 1.0 else: 1.0 / (procSysStat().cpu.len.float - 1.0)
  cf.parseColor                                   #.color => .attr
  cf.parseFormat                                  #.format => .fields
  cs = cf.addr                                    #Init global ptr

proc read*(p: var Sys, need: SysSrcs): bool =
  if ssMemInfo  in need: p.m = procMemInfo()
  if ssStat     in need: p.s = procSysStat()
  if ssLoadAvg  in need: p.l = procLoadAvg()
  if ssDiskStat in need: p.d = procDiskStats()
  if ssNetDev   in need: p.n = procNetDevStats()
  return true

proc scrollSys*(cf: var ScCf) =
  ## Scrolling system-wide statistics like dstat/vmstat/iostat/etc.  Default
  ## format is scheduled jiffies, load, memory, CtxSwch, disk&net-IO, but user
  ## can define many of their own styles/bundles.  Like many utilities in this
  ## genre, the very first report row is "since boot up".
  var last, curr: Sys
  var t, t0: MonoTime
  var dtI: float
  for it in 0 ..< cf.numIt:
    if cf.frqHdr > 0 and it mod cf.frqHdr == 0:
      stdout.write cf.headers
    if not curr.read(cf.need):
      stdout.write "COULD NOT UPDATE; NEXT ITERATION COVERS >1 INTERVAL\n"
      nanosleep(cf.delay)
      continue
    t   = getMonoTime()                 #update time & dtI
    dtI = if it == 0: 1.0 else: 1e9 / (t.ticks - t0.ticks).float
    t0  = t
    for i, f in cf.fields:
      if i != 0: stdout.write ' '
      stdout.write f.fmt(dtI, f.wid, last, curr)
    stdout.write '\n'
    stdout.flushFile
    if it + 1 < cf.numIt:
      last = curr
      nanosleep(cf.delay)

when isMainModule:                      ### DRIVE COMMAND-LINE INTERFACE
  import cligen, cligen/cfUt

  proc mergeParams(cmdNames: seq[string],
                   cmdLine=os.commandLineParams()): seq[string] =
    if cmdNames.len > 0:
      if cmdNames[0] == "multi":
        let bn = paramStr(0).lastPathPart
        if   bn == "pd": result.add "display"
        elif bn in ["sc", "scroll", "scrollsy"]: result.add "scrollsy"
        elif bn == "pf": result.add "find"
        elif bn == "pk": result.add [ "find", "-akill" ]
        elif bn == "pw": result.add [ "find", "-await" ]
        return result & cmdLine
      let underJoin = strutils.toUpperAscii(cmdNames.join("_"))
      var cfPath = os.getEnv(underJoin & "_CONFIG")   #See if cfg file redirect
      if cfPath.len == 0:                             #..else use getConfigDir
        cfPath = os.getConfigDir() / cmdNames[0] / "config"   #See if dir w/cfg
        if not fileExists(cfPath): cfPath = cfPath[0..^8]     #..else use file
      result.add cfToCL(cfPath, if cmdNames.len > 1: cmdNames[1] else: "",
                        quiet=true, noRaise=true)
      result.add envToCL(underJoin) #Finally add $PROCS_DISPLAY $PROCS_FIND..
    result = result & cmdLine       #and then whatever user entered

  const nimbleFile = staticRead "procs.nimble"
  clCfg.version = nimbleFile.fromNimble "version"

  proc c_getenv(env: cstring): cstring {.importc:"getenv", header:"<stdlib.h>".}
  let noColor = c_getenv("NO_COLOR") != nil
  let tsM1 = Timespec(tv_sec: (-1).Time)
  let tsP1 = Timespec(tv_sec: (+1).Time)

  let dd = DpCf(header: true, indent: 3, plain: noColor, delay: tsM1)
  initDispatchGen(displayCmd, cf, dd, positional="pids", @["ALL AFTER pids"]):
    cf.fin()
    cf.display()
    quit(0)

  let sd = ScCf(frqHdr: 15, numIt: -1, plain: noColor, delay: tsP1)
  initDispatchGen(scrollC, cf, sd, positional="format", @["ALL AFTER format"]):
    cf.fin()
    cf.scrollSys()
    quit(0)

  const ess: seq[string] = @[]
  dispatchMulti(
    [ displayCmd, cmdName="display", doc=docFromProc(procs.display),
      help = { "kind":  """proc kinds: NAME<WS>RELATION<WS>PARAMS
where <RELATION> says processes match:
  any|all|none  earlier defd test names
BUILTIN: sleep run stop zomb niced MT L kern""",
               "colors" : "color aliases; Syntax: name = ATTR1 ATTR2..",
               "color"  : """text attrs for proc kind/fields. Syntax:
  NAME[[:KEY][:DIM]]<WS>ATTR<WS>ATTR..
NAME=kind nm as above|size{BKMGT}
KEY=0..255 sort/ord key,DIM=dimensionNo.
ATTR=attr specs as above""",
               "ageFmt":"""Syntax: PROCAGE'@'[-+]STRFTIMEFMT where:
  PROCAGE in {seconds, 'ANYTIME'},
  + means Duration, - means plain mode,
  %CODEs are any strftime + %<DIGIT>.""",
               "format" : "\"%[-]a %[-]b\" l/r aligned fields to display",
               "order"  : "[-]x[-]y[-]z.. keys to sort procs by",
               "diffCmp": "[-]x[-]y[-]z.. keys to diff by w/delay",
               "binary" : "K=size/1024,M=size/1024/1024 (vs/1000..)",
               "wide"   : "%C does not truncate to terminal width",
               "plain"  : "plain text; aka no color Esc sequences",
               "header" : "add row at start of data with col names",
               "indent" : "per-level depth-indentation",
               "width"  : "override auto-detected terminal width",
               "delay"  : "seconds between differential reports",
               "maxUnm" : "like maxName for user names",
               "maxGnm" : "like maxName for group names",
               "excl"   : "kinds to exclude",
               "incl"   : "kinds to include",
               "merge"  : "merge rows within these kind:dim",
               "hdrs"   : "<1-ch-code>:<headerOverride> pairs",
               "realIds": "use real uid/gid from /proc/PID/status" },
      short = { "width":'W', "indent":'I', "incl":'i', "excl":'x', "header":'H',
                "maxUnm":'U', "maxGnm":'G', "version":'v', "colors":'C',
                "diffcmp":'D' },
      alias = @[ ("Style", 'S', "DEFINE an output style arg bundle", @[
                   @[ "io" , "-DJ><", "-f%p %t %< %> %J %c" ] ]),   #built-ins
                 ("style", 's', "APPLY an output style" , @[ess]) ] ],
    [ procs.find, cmdName="find", doc=docFromProc(procs.find),
      help = { "pids":      "whitespace separated PIDs to subset",
               "full":      "match full command name",
               "ignoreCase":"ignore case in matching patterns",
               "parent":    "match only kids of given parent",
               "pgroup":    "match process group IDs",
               "session":   "match session IDs",
               "tty":       "match by tty",
               "group":     "match real group|group IDs",
               "euid":      "match by effective user|UIDs",
               "uid":       "match by real user|UIDs",
               "root":      "match procs with same root as given PID",
               "ns":        "match procs in given NS of given PID",
               "ns-list":   "for --ns: ipc mnt net pid user uts cgroup",
               "first":     "select first matching PID",
               "newest":    "select most recently started",
               "oldest":    "select least recently started",
               "exclude":   "omit these PIDs {PPID=>par&pgrp(this)}",
               "inVert":    "inVert/negate the matching (like grep -v)",
               "delim":     "put after each output PID",
               "delay":     "seconds between signals/existence chks",
               "signals":   "signal names/numbers (=>actions.add kill)",
               "nice":      "nice increment (!=0 =>actions.add nice)",
               "actions":   "echo/count/kill/nice/wait/Wait" },
      short = { "parent":'P', "pgroup":'g', "group":'G', "euid":'u', "uid":'U',
                "ns":'\0', "nsList":'\0', "first":'1', "exclude":'x',
                "inVert":'v', "delay":'D', "session":'S', "nice":'N' } ],
    [ scrollC, cmdName="scrollsy", doc=docFromProc(procs.scrollSys),
      help = { "colors": "color aliases; Syntax: name = ATTR1 ATTR2..",
               "color" : """attrs for size/load fields.  Syntax:
  NAME<WS>ATTR<WS>ATTR..
NAME = size{BKMGT}|load{NNN}
ATTR = as in `lc` colors""",
               "frqHdr": "frequency of header repeats",
               "numIt" : "number of reports",
               "delay" : "delay between reports",
               "binary": "K=size/1024,M=size/1024/1024 (vs/1000..)",
               "unnorm": "do not normalize jiffy times/loads by #CPUs",
               "plain" : "plain text; aka no color Esc sequences",
               "hdrs"  : "<OLD_HEADER>:<MY_HEADER> pairs",
               "disks" : "PerlCmpatRx's of disks to total; {}=all",
               "ifaces": "PerlCmpatRx's of interfaces to total; {}=all",
               "format": "fmt1 [fmt2..] formats to query & print" },
      short = {"colors": 'C', "hdrs": 'H', "disks": 'k'},
      alias = @[ ("Style", 'S', "DEFINE an output style arg bundle", @[ess]),
                 ("style", 's', "APPLY an output style" , @[ess]) ]  ])
