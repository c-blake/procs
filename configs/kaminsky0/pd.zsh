function pd() {
    local PD_LABELS_AWK="$ZDOTDIR/pd-labels.awk"
    local PD_LABELS_ROLLUPS="$ZDOTDIR/pd-rollups"

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
    declare -a maplist=()
    declare -a arglist=()
    declare -a labels=("${(k)rollups[@]/#/-L }")
    declare -a patterns=("${(v)rollups[@]}")
    declare -a ru_pids=($(pf -f "$labels[@]" "${patterns[@]}"))

    for ru_pid in $ru_pids; do
        declare -a parts=(${(@s/:/)ru_pid}) 
        local ru_lab="${parts[1]}"
        local ru_pid="${parts[2]}"

        if [[ "$ru_pid" == "None" ]]; then
            arglist+=(
                -k\^="${ru_lab}_ any unknown"
            )
        else
            maplist+=("map[$ru_pid] = \"${ru_lab}\";\n")
            arglist+=(
                -k\^="${ru_lab} all ${ru_lab}_1 notexplicit"
                -k\^="${ru_lab}_1 pcr_l ${ru_lab}:"
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

    if [[ -z $input ]]; then
        declare -a pids=(
            $(pf -ap "" | \
                mawk -f <(echo $map) -f $PD_LABELS_AWK
            )
        )
        command pd -s user ${arglist[@]} $flags ${pids[@]}
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
