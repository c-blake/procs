function pd() {
    local PD_LABELS_AWK="$HOME/.zsh/pd-labels.awk"
    local PD_LABELS_ROLLUPS="$HOME/.zsh/pd-rollups"

    local input
    declare -a flags
    for arg in "$@"; do
        if [[ ${arg:0:1} == "-" ]]; then
            flags+=$arg
        else
            input=$arg
        fi
    done

    #date --iso=ns
    eval "declare -A rollups=($(< $PD_LABELS_ROLLUPS))"
    declare -a maplist=()
    declare -a arglist=()
    for ru_k ru_v in ${(kv)rollups}; do
        #echo $ru_k " -> " $ru_v
        declare -a letters=( "" A B C D E F G H I J K L M N O P Q R S T U V W X Y Z )
        local ru_pids=($(pf -f $ru_v))
        for ru_pid in $ru_pids; do
            local letter="${letters[1]}"
            shift letters

            #echo $letter

            local ll="${ru_k}_${letter}"

            maplist+=("map[$ru_pid] = \"${ll}\";\n")
            arglist+=(
                -k\^="${ll} all ${ll}_1 notexplicit"
                -k\^="${ll}_1 pcr_l ${ll}:"
                -m\^="${ll}"
                -c\^="${ll}:0x0:3 inverse"
            )
        done
    done
    local map="BEGIN { $maplist }"
    arglist+=(
        -k\^="notexplicit none explicit"
        -k\^="explicit pcr_l explicit:"
    )
    #date --iso=ns

    #echo $arglist
    #echo $map

    if [[ -z $input ]]; then
        declare -a pids=(
            $(pf -ifap "" | \
                awk -f <(echo $map) -f $PD_LABELS_AWK
            )
        )
        command pd -s user ${arglist[@]} $flags ${pids[@]}
    #date --iso=ns

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
                awk -f <(echo $map) -v prefix=explicit -f $PD_LABELS_AWK
            )
        )

        if [[ -z $pids ]]; then
            echo "No processes match pattern: $process"
            return 1
        fi

        command pd -s user --format\^="@@%l@@" -W=$[COLUMNS+34] ${arglist[@]} $flags $pids |\
        sed -E \
            -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/\x1b\[(..|)m//g" \
            -e "/^@@.*explicit:.*@@|@@LABELS.*@@/I! s/.*/\x1b[38:5:242m&\x1b[m/g" \
            -e "s/$process/\x1b[4:1;58:5:208m&\x1b[4:0m/gI" \
            -e "s/@@.+@@//"
    fi
}
