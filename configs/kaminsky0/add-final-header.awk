#!/usr/bin/awk -f

# This script copies its input to its output, like cat, with one
# addition:  It assumes that the first line of the input is a header,
# which it repeats (inserts) n lines from the end of the output. The
# motivation is that sometimes you want to "cat" a file or display
# program's output that contains tabular data, but you don't want to
# have to scroll back the terminal to see the column headers.
#
# EXAMPLE USAGE:
#   $ ps axuw | add-final-header.awk $(($LINES - 3))
#   $ lsof -nu kaminsky | add-final-header.awk $(($LINES - 3))

# Check if n is provided as an argument
BEGIN {
    if (ARGC < 2) {
        print "Usage: add-final-header.awk n"
        exit 1
    }
    n = ARGV[1]
    delete ARGV[1]  # Remove n from ARGV to avoid processing it as input
}

# Count the total number of lines
{ lines[count++] = $0 }

# At the end of the input, print all lines
END {
    for (i = 0; i < count; i++) {
        print lines[i]
        # Print the first line n lines from the end
        if (i == count - n) {
            print lines[0]
        }
    }
}
