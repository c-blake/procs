function pd() {
    local PD_LABELS_AWK="$ZDOTDIR/pd-labels.awk"
    local PD_LABELS_ROLLUPS="$ZDOTDIR/pd-rollups"
    local PD_LABELS_STALE=${PD_LABELS_STALE:-10} # seconds
    local PFA=${PFA:-/dev/shm/proc.kaminsky.cpio}

    eval "declare -A rollups=($(< $PD_LABELS_ROLLUPS))"
    declare -a labels=("${(k)rollups[@]/#/-L }")
    declare -a patterns=("${(v)rollups[@]}")
    #print -l ${labels[@]}
    #print -l ${patterns[@]}

    # Cache the PFA archive (see PD_LABELS_STALE above & elif below)
    declare -A pfa_stat
    [[ -f $PFA ]] && zstat -H pfa_stat $PFA
    local pfa_mtime_delta=$[EPOCHREALTIME-pfa_stat[mtime]]

    # See if the user set a PFS before calling us; if so, use that
    if [[ -n "$PFS" ]]; then
        unset PFA
        declare -a ru_pids=($(pf -f "$labels[@]" "${patterns[@]}"))
    # Use cached version if it's < 1 minute old
    elif [[ -f $PFA && $pfa_mtime_delta -lt $PD_LABELS_STALE ]]; then
        local PFS=$PFA 
        unset PFA
        declare -a ru_pids=($(pf -f "$labels[@]" "${patterns[@]}"))
    else
        declare -a ru_pids=($(pf \
            -F,=,dst,stat,exe,io,sched -A-99999999900 \
            -f "$labels[@]" "${patterns[@]}"
        ))
        local PFS=$PFA 
        unset PFA
    fi
    #print -l ${ru_pids[@]}

    declare -a maplist=()
    declare -a arglist=()
    for ru_pid in $ru_pids; do
        declare -a parts=(${(@s/:/)ru_pid}) 
        local ru_lab="${parts[1]/_0/}"
        local ru_pid="${parts[2]}"

        if [[ "$ru_pid" == "None" ]]; then
            arglist+=(
                -k\^="${ru_lab} any unknown"
            )
        else
            maplist+=("map[$ru_pid] = \"${ru_lab}\";\n")
            arglist+=(
                -k\^="${ru_lab} all ${ru_lab}__base notexplicit"
                -k\^="${ru_lab}__base pcr_l ${ru_lab}:"
                -m\^="${ru_lab}"
                -c\^="${ru_lab}:0x0:3 inverse"
            )
        fi
    done

    local map="BEGIN { $maplist }"
    arglist+=(
        -k\^="notexplicit none explicit"
        -k\^="explicit pcr_l explicit:"
    )
    #echo $arglist
    #echo $map

    local input
    declare -a flags

    for arg in "$@"; do
        if [[ ${arg:0:1} == "-" ]]; then
            flags+=$arg
        else
            input=$arg
        fi
    done

    if [[ -z $input ]]; then
        declare -a pids=(
            $(pf -ap "" | \
                mawk -f <(echo $map) -f $PD_LABELS_AWK
            )
        )
        pids=($(printf "%s\n" "${pids[@]}" | sort | uniq))

        command pd -s user "${arglist[@]}" "${flags[@]}" "${pids[@]}"

    else
        local process scope scope_pids

        # input is either a process or scope::process
        declare -a parsed=(${(@s/::/)input})
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

        declare -a pids=(
            $(pf -ifap $process | \
                grep -Ew "${scope_pids}" | \
                mawk -f <(echo $map) -v prefix=explicit -f $PD_LABELS_AWK
            )
        )
        pids=($(printf "%s\n" "${pids[@]}" | sort | uniq))

        if [[ -z $pids ]]; then
            echo "No processes match pattern: $process"
            return 1
        fi

        command pd -s user --format\^="@@%l@@" -W=$[COLUMNS+34] ${arglist[@]} $flags $pids | \
            sed -E \
                -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/\x1b\[(..|)m//g" \
                -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/.*/\x1b[38:5:242m&\x1b[m/g" \
                -e "s/$process/\x1b[4:1;58:5:208m&\x1b[4:0m/gI" \
                -e "s/@@.+@@//"
    fi
}

# vi:ft=zsh
