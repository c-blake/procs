# This script is written for mawk; the gawk version was much slower.

BEGIN {
  sep = ":"
}

{
  if (prefix) {
    $0 = prefix sep $0;
  }

  for (pid in map) {
    if ($0 ~ "(^| )" pid "( |$)") {
      for (i = 1; i <= NF; i++) {
        gsub(/[0-9]+$/, map[pid] sep "&", $i);
        if ($i == map[pid] sep pid) {
          break;
        };
      }
    }
  }

  print $0;
}
