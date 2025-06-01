function _pd() {
    local PD_LABELS_AWK="$ZDOTDIR/pd-labels.awk"
    local PD_LABELS_ROLLUPS="$ZDOTDIR/pd-rollups"
    local PD_LABELS_STALE=${PD_LABELS_STALE:-10} # seconds
    local PFA=${PFA:-/dev/shm/pfs-$USER.cpio}

    #local start_time
    #start_time=$EPOCHREALTIME

    local input
    declare -a flags

    for arg in "$@"; do
        if [[ ${arg:0:1} == "-" ]]; then
            flags+=$arg
        else
            input=$arg
        fi
    done

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
        declare -a ru_pids=($(pf -f "${labels[@]}" "${patterns[@]}"))
    else
        # Use cached version if it's < 1 minute old
        if [[ ! -f $PFA || $pfa_mtime_delta -gt $PD_LABELS_STALE ]]; then
            local SMR=""
            [[ $flags == *"-smem"* ]] && SMR="r/smaps_rollup"
            parc sys/kernel/pid_max uptime meminfo -- \
                s/ r/stat R/exe r/cmdline r/io r/schedstat $SMR \
                > $PFA
        fi

        local PFS=$PFA 
        unset PFA
        declare -a ru_pids=($(pf -f "${labels[@]}" "${patterns[@]}"))
    fi

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
        elif [[ "$ru_lab" == _* ]]; then
            # If label starts with _, don't create a new rollup; instead,
            # add the PID to the "first" rollup for the given label.
            maplist+=("map[$ru_pid] = \"${${ru_lab#_}%_*}\";\n")
        else
            maplist+=("map[$ru_pid] = \"${ru_lab}\";\n")
            arglist+=(
                -k\^="${ru_lab} all ${ru_lab}__base notexplicit"
                -k\^="${ru_lab}__base pcr_l ${ru_lab}:"
                -m\^="${ru_lab}"
                -c\^="${ru_lab}:0x0:3 ru_color"
                #-c\^="${ru_lab}:0x0:3 ru_color over underdot"
                #-c\^="${ru_lab}:0x0:3 underline cmdclr" # b242888"
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

    #echo $[EPOCHREALTIME-start_time]

    if [[ -z $input ]]; then
        #start_time=$EPOCHREALTIME

        declare -a pids=(
            $(pf -ap "" | \
                mawk -f <(echo $map) -f $PD_LABELS_AWK
            )
        )
        # The -U flag to declare/typeset removes duplicates. Note
        # that we cannot put that -U in the previous declare line,
        # since that will deduplicate before labels are added.
        declare -U -a pids=(${(on)pids})
        #pids=($(printf "%s\n" "${pids[@]}" | sort | uniq))

        #echo $[EPOCHREALTIME-start_time]

        #start_time=$EPOCHREALTIME

        command pd -s user "${arglist[@]}" "${flags[@]}" "${pids[@]}" | \
            sed -E -e "/^USER/ s/.*/\x1b[38:5:220;1;4m&\x1b[m/g"

        #echo $[EPOCHREALTIME-start_time]

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
        #print -l "${pids[@]}"
        # The -U flag to declare/typeset removes duplicates. Note
        # that we cannot put that -U in the previous declare line,
        # since that will deduplicate before labels are added.
        declare -U -a pids=(${(on)pids})

        if [[ -z $pids ]]; then
            echo "No processes match pattern: $process"
            return 1
        fi

        #start_time=$EPOCHREALTIME
        command pd -s user --format\^="@@%l@@" -W=$[COLUMNS+34] ${arglist[@]} "${flags[@]}" "${pids[@]}" | \
            sed -E \
                -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/\x1b\[(..|039|38;2;[0-9]+;[0-9]+;0|)m//g" \
                -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/.*/\x1b[38:5:242m&\x1b[m/g" \
                -e "/^@@LABELS.*@@/ s/.*/\x1b[38:5:220;1;4m&\x1b[m/g" \
                -e "s/$process/\x1b[4:1;58:5:208m&\x1b[4:0m/gI" \
                -e "s/@@.+@@//"
        #echo $[EPOCHREALTIME-start_time]
    fi

    #echo $[EPOCHREALTIME-start_time]
}

function pd() {
    # repeat header if stdout is a terminal
    if [[ -t 1 ]]; then
        _pd "$@" | add-final-header.awk $[$LINES-3]
    else
        _pd "$@"
    fi
}

function pdl() {
    _pd "$@"| LESS_LINES=$[$LINES-2] less --header=1,52 -F --redraw-on-quit -X
}

# vi:ft=zsh
