# Package
version     = "0.5.7"
author      = "Charles Blake"
description = "Unix process&system query&formatting library&multi-command CLI in Nim"
license     = "MIT/ISC"
bin         = @[ "procs" ]

# Dependencies
requires "nim >= 1.6.0", "cligen >= 1.6.12"
skipDirs = @["configs"]
