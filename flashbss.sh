
for a in "${ALGOS[@]}"; do
    read -r F B < <(build_and_measure "$a")
    df=$((F-BASE_F))
    db=$((B-BASE_B))
    # Only attribute shared overhead to algorithms that actually linked it in
    if [ "$db" -ge "$((RT_B-BASE_B))" ]; then
        db=$((db - (RT_B-BASE_B)))
        df=$((df - (RT_F-BASE_F)))
        tag="uses shared runtime"
    else
        tag="no shared runtime"
    fi
    echo "$a: flash=$df bss=$db ($tag)"
done
