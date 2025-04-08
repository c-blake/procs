function pd() {
    local PD_LABELS_AWK="$HOME/.zsh/pd-labels.awk"

    local input
    typeset -a flags
    for arg in "$@"; do
        if [[ ${arg:0:1} == "-" ]]; then
            flags+=$arg
        else
            input=$arg
        fi
    done
    
    local map ff_w ff_h code chrome
    ff_w=$(pf -1f /firefox$)
    ff_h=$(pf -1f /firefox\ -P)
    code=$(pf -1f /code$)
    chrome=$(pf -1 chrome$)

    map=$(cat << EOF
    BEGIN {
      map[$ff_w] = "ff_w"
      map[$ff_h] = "ff_h"
      map[$code] = "code"
      map[$chrome] = "chrome"
  }
EOF
)
    if [[ -z $input ]]; then
        local pids
        pids=(
            $(pf -ifap "" | \
                awk -f <(echo $map) -f $PD_LABELS_AWK
            )
        )
        command pd -s user $flags $pids
    else
        local parsed process pids scope scope_pids

        # input is either a process or scope::process
        parsed=(${(@s/::/)input})
        if [[ ${#parsed[@]} -eq 1 ]]; then
            process=$parsed[1]
            scope=""
            scope_pids=""
        else
            process=$parsed[2]
            scope=$parsed[1]
            scope_pids=$(pf -if -d'|' "$scope")
            scope_pids="${scope_pids%|}"   # remove final |
        fi

        pids=(
            $(pf -ifap $process | \
                grep -Ew "${scope_pids}" | \
                awk -f <(echo $map) -v prefix=explicit -f $PD_LABELS_AWK
            )
        )

        if [[ -z $pids ]]; then
            echo "No processes match pattern: $process"
            return 1
        fi

        command pd -s user --format\^="__%l__" -W=$[COLUMNS+34] $flags $pids |\
        sed -E \
            -e "/^__.*explicit:.*__|__LABELS.*__/I! s/\x1b\[(..|)m//g" \
            -e "/^__.*explicit:.*__|__LABELS.*__/I! s/.*/\x1b[38:5:242m&\x1b[m/g" \
            -e "s/$process/\x1b[4:1;58:5:208m&\x1b[4:0m/gI" \
            -e "s/__.+__//"
    fi
}

