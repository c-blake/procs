# Package
version     = "0.5.3"
author      = "Charles Blake"
description = "Unix process&system query&formatting library&multi-command CLI in Nim"
license     = "MIT/ISC"
bin         = @[ "procs" ]

# Dependencies
requires "nim >= 0.20.2", "cligen >= 1.5.37"
skipDirs = @["configs"]
