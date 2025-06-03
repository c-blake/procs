# Package
version     = "0.8.8"
author      = "Charles Blake"
description = "Unix process&system query&format lib&multi-command CLI in Nim"
license     = "MIT/ISC"
bin         = @["procs"]
installDirs = @["configs"]

# Dependencies
requires "nim >= 1.6.0", "cligen >= 1.8.5"
skipDirs = @["configs"]

import std/[os, strutils] #XXX from os import parentDir, getEnv, dirExists fails
proc getNimbleDir: string =
  result = getEnv("NIMBLE_DIR", getEnv("nimbleDir", ""))
  if result.len > 0: return
  if (let (installDir, ex) = gorgeEx("nimble path procs"); ex == 0):
    result = installDir.strip.parentDir.parentDir  # Hopefully .ini nimbleDir

# Next bits populate an `etc/procs/` directory used by `procs` If a user gives
# neither config nor CLI options.  `procs` finds this from /proc/PID | $0 which
# may not work in all OS/shells (then users just do not get a fallback config).
proc getEtcDir: string =
  result = getEnv("ETC_DIR", getEnv("ETCDIR", getEnv("etcDir", "")))
  if result.len > 0: return
  let nD = getNimbleDir()
  if nD.len == 0: return
  let etc = nD & "/../etc"                      # $(HOME|/opt)/etc
  result = if etc.dirExists: etc & "/procs" else: nD & "/../etc/procs"

task installConf, "install the default config in \".../etc/procs/\"":
  let cD = getEtcDir()                          # .../etc/procs
  if cD.dirExists or cD.fileExists:
    echo "\n", cD, " ALREADY EXISTS\nRename/Remove/uninstallConf & try again"
  elif cD.len > 0:
    exec "umask 022 && mkdir -p " & cD & " && install -m644 configs/cb0/* " & cD
  else: echo """ERROR: Could not infer ETC_DIR;
Try doing `nimble install procs` first
or try `ETC_DIR=/x/y/etc nimble installConf`"""; return

task uninstallConf, "uninstall the default config from \".../etc/procs/\"":
  let cD = getEtcDir(); let pD = cD.parentDir   # rmdir in case we spammed $HOME
  if dirExists(cD): exec "rm -vr " & cD & " && rmdir -v "  & pD & ";:"

task installData, "installConf": installConfTask()
task uninstallData, "uninstallConf": uninstallConfTask()

# On a barely responsive system "pk X" can be VERY nice cmp to "procs f -ak X",
# especially killing can restore responsiveness, but shell aliases also exist.
task makeLinks, "make symlinks to \".../bin/procs\"":
  let nB = getNimbleDir() / "bin"
  echo "making symlinks in ", nB
  for base in ["pd", "pf", "pk", "pw", "sc"]:
    exec "cd " & nB & " && ln -s procs " & base & " || :"

task unmakeLinks, "unmake symlinks to \".../bin/procs\"":
  let nB = getNimbleDir() / "bin"
  for base in ["pd", "pf", "pk", "pw", "sc"]:
    exec "[ \"$(readlink " & (nB/base) & ")\" = procs ] && rm -fv " & (nB/base)

# Allow nimble to drive both man & conf installation if it has permission.
proc absent(evs: openArray[string]): bool =             # True if *NONE* of evs
  result = true
  for ev in evs: result = result and not ev.existsEnv   #..is set to anything.

after install:          # Evidently, `after uninstall:` is not honored
  if ["NIMBLE_MINI","mini"].absent:
    if ["NIMBLE_NOLN","noln"].absent: makeLinksTask()
    if ["NIMBLE_NOETC","noetc","NIMBLE_NOCONF","noconf"].absent: installConfTask()
