#!/bin/sh
set -eu

export LC_ALL=C

runtime_closure_fail() {
    printf '%s\n' 'BLOCKED:DEVCONTAINER_RUNTIME_CLOSURE' >&2
    exit 1
}

if [ "$#" -lt 3 ]
then
    runtime_closure_fail
fi

runtime_packages_file="$1"
runtime_root="$2"
shift 2

runtime_binary_candidates_file=
runtime_elf_magic_file=
runtime_ldd_output_file=
runtime_dependencies_file=
runtime_package_candidates_file=
runtime_package_matches_file=
runtime_packages_staging_file=
runtime_closure_complete=false

cleanup_runtime_closure() {
    for runtime_temp_file in \
        "$runtime_binary_candidates_file" \
        "$runtime_elf_magic_file" \
        "$runtime_ldd_output_file" \
        "$runtime_dependencies_file" \
        "$runtime_package_candidates_file" \
        "$runtime_package_matches_file" \
        "$runtime_packages_staging_file"
    do
        if [ -n "$runtime_temp_file" ]
        then
            rm -f -- "$runtime_temp_file"
        fi
    done
    if [ "$runtime_closure_complete" != true ] && [ -n "$runtime_packages_file" ]
    then
        rm -f -- "$runtime_packages_file"
    fi
}
trap cleanup_runtime_closure EXIT
trap 'exit 1' HUP INT TERM

case "$runtime_packages_file" in
    /*) ;;
    *) runtime_closure_fail ;;
esac
case "$runtime_root" in
    /*) ;;
    *) runtime_closure_fail ;;
esac

rm -f -- "$runtime_packages_file" || runtime_closure_fail
runtime_root="$(readlink -f -- "$runtime_root" 2>/dev/null)" \
    || runtime_closure_fail
test -d "$runtime_root" || runtime_closure_fail

runtime_binary_candidates_file="$(mktemp)" || runtime_closure_fail
runtime_elf_magic_file="$(mktemp)" || runtime_closure_fail
runtime_ldd_output_file="$(mktemp)" || runtime_closure_fail
runtime_dependencies_file="$(mktemp)" || runtime_closure_fail
runtime_package_candidates_file="$(mktemp)" || runtime_closure_fail
runtime_package_matches_file="$(mktemp)" || runtime_closure_fail
runtime_packages_staging_file="$(mktemp)" || runtime_closure_fail

: > "$runtime_binary_candidates_file"
for runtime_binary_candidate in "$@"
do
    case "$runtime_binary_candidate" in
        /*) ;;
        *) runtime_closure_fail ;;
    esac
    test -e "$runtime_binary_candidate" || runtime_closure_fail
    test -f "$runtime_binary_candidate" || runtime_closure_fail
    if ! od -An -v -tx1 -N4 -- "$runtime_binary_candidate" \
        > "$runtime_elf_magic_file" 2>/dev/null
    then
        runtime_closure_fail
    fi
    if ! awk '
        NR == 1 && NF == 4 &&
        $1 == "7f" && $2 == "45" && $3 == "4c" && $4 == "46" {
            elf_magic = 1
        }
        END { exit elf_magic == 1 ? 0 : 1 }
    ' "$runtime_elf_magic_file"
    then
        runtime_closure_fail
    fi
    printf '%s\n' "$runtime_binary_candidate" \
        >> "$runtime_binary_candidates_file"
done
sort -u -o "$runtime_binary_candidates_file" "$runtime_binary_candidates_file" \
    || runtime_closure_fail
test -s "$runtime_binary_candidates_file" || runtime_closure_fail

: > "$runtime_dependencies_file"
while IFS= read -r runtime_binary_candidate
do
    if ! ldd "$runtime_binary_candidate" \
        > "$runtime_ldd_output_file" 2>&1
    then
        runtime_closure_fail
    fi
    runtime_not_found_status=0
    grep -F 'not found' "$runtime_ldd_output_file" >/dev/null 2>&1 \
        || runtime_not_found_status="$?"
    case "$runtime_not_found_status" in
        0) runtime_closure_fail ;;
        1) ;;
        *) runtime_closure_fail ;;
    esac
    if ! awk '
        $2 == "=>" && $3 ~ /^\// { print $3; next }
        $1 ~ /^\// { print $1 }
    ' "$runtime_ldd_output_file" >> "$runtime_dependencies_file"
    then
        runtime_closure_fail
    fi
done < "$runtime_binary_candidates_file"

sort -u -o "$runtime_dependencies_file" "$runtime_dependencies_file" \
    || runtime_closure_fail
test -s "$runtime_dependencies_file" || runtime_closure_fail

: > "$runtime_package_candidates_file"
while IFS= read -r runtime_dependency
do
    normalized_dependency="$(readlink -f -- "$runtime_dependency" 2>/dev/null)" \
        || runtime_closure_fail
    test -e "$normalized_dependency" || runtime_closure_fail
    case "$normalized_dependency" in
        "$runtime_root"/*) continue ;;
    esac

    runtime_package_owner_found=false
    runtime_previous_package_candidate=
    for runtime_package_candidate in \
        "$runtime_dependency" "$normalized_dependency"
    do
        if [ "$runtime_package_candidate" = "$runtime_previous_package_candidate" ]
        then
            continue
        fi
        runtime_previous_package_candidate="$runtime_package_candidate"
        : > "$runtime_package_matches_file"
        if ! dpkg-query --search "$runtime_package_candidate" \
            > "$runtime_package_matches_file" 2>/dev/null
        then
            continue
        fi
        if runtime_packages_for_candidate="$(awk '
            function trim(value) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                return value
            }
            {
                owner_separator = index($0, ": ")
                if (owner_separator == 0) {
                    next
                }
                owner_list = substr($0, 1, owner_separator - 1)
                owner_count = split(owner_list, owners, ",")
                valid_owner_list = 1
                for (owner_index = 1; owner_index <= owner_count; owner_index++) {
                    owners[owner_index] = trim(owners[owner_index])
                    if (owners[owner_index] !~ \
                        /^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$/) {
                        valid_owner_list = 0
                    }
                }
                if (valid_owner_list == 1) {
                    for (owner_index = 1; owner_index <= owner_count; owner_index++) {
                        print owners[owner_index]
                    }
                }
            }
        ' "$runtime_package_matches_file")"
        then
            if [ -n "$runtime_packages_for_candidate" ]
            then
                printf '%s\n' "$runtime_packages_for_candidate" \
                    >> "$runtime_package_candidates_file"
                runtime_package_owner_found=true
            fi
        fi
    done
    test "$runtime_package_owner_found" = true || runtime_closure_fail
done < "$runtime_dependencies_file"

sort -u "$runtime_package_candidates_file" > "$runtime_packages_staging_file" \
    || runtime_closure_fail
test -s "$runtime_packages_staging_file" || runtime_closure_fail
mv -f -- "$runtime_packages_staging_file" "$runtime_packages_file" \
    || runtime_closure_fail
test -s "$runtime_packages_file" || runtime_closure_fail
runtime_closure_complete=true
