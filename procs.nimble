# Package
version     = "0.1"
author      = "Charles Blake"
description = "Unix process&system query&formatting library&multi-command CLI in Nim"
license     = "MIT/ISC"
bin         = @[ "procs" ]

# Dependencies
requires "nim >= 0.20.0", "cligen#head"
skipDirs = @["configs"]
