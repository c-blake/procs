# Package
version     = "0.3.0"
author      = "Charles Blake"
description = "Unix process&system query&formatting library&multi-command CLI in Nim"
license     = "MIT/ISC"
bin         = @[ "procs" ]

# Dependencies
requires "nim >= 0.20.0", "cligen >= 1.2.0"
skipDirs = @["configs"]
