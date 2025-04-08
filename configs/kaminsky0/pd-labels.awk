BEGIN {
  sep = ":"
}

{
  if (prefix) {
    $0 = prefix sep $0;
  }

  for (pid in map) {
    if ($0 ~ pid) {
      f = 0;
      for (i = 1; i <= NF; i++) {
        if (f == 0) {
          $i = gensub(/[0-9]+/, map[pid] sep "&", "g", $i);
        }
        if ($i == map[pid] sep pid) {
          f = 1;
        };
      }
    }
  }

  print $0;
}
