#!/bin/sh
# Collect local Linux resource counters in two snapshots around a benchmark.
set -eu
export LC_ALL=C

usage() {
    printf 'Usage: sh flr-relay-counters.sh --seconds 1-120 --interface DEVICE [--interface DEVICE ...]\n' >&2
    exit 2
}

seconds=
devices=
count=0
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || usage
    case "$1" in
        --seconds)
            [ -z "$seconds" ] || usage
            case "$2" in ''|*[!0-9]*) usage ;; esac
            [ "${#2}" -le 3 ] && [ "$2" -ge 1 ] && [ "$2" -le 120 ] || usage
            seconds=$2
            ;;
        --interface)
            case "$2" in ''|.|..|-*|*[!a-zA-Z0-9_.-]*) usage ;; esac
            [ "${#2}" -le 15 ] && [ "$count" -lt 4 ] || usage
            case " $devices " in *" $2 "*) usage ;; esac
            devices="${devices:+$devices }$2"
            count=$((count + 1))
            ;;
        *) usage ;;
    esac
    shift 2
done
[ -n "$seconds" ] && [ "$count" -gt 0 ] || usage

# Override the virtual filesystem roots for fixture tests.
proc=${FLR_BENCH_PROC_ROOT:-/proc}
net=${FLR_BENCH_NET_ROOT:-/sys/class/net}
if [ ! -r "$proc/uptime" ] || [ ! -r "$proc/stat" ] || [ ! -r "$proc/net/dev" ]; then
    printf 'Linux /proc uptime, stat and net/dev are required\n' >&2
    exit 1
fi

qdisc_snapshot() {
    # Only a completed command can contribute counters. Bound the wait and
    # parse the root qdisc only, so child queues cannot duplicate its totals.
    (timeout -k 1 1 tc -s qdisc show dev "$1" && printf '\nFLR_QDISC_DONE\n') 2>/dev/null |
        awk -v device="$1" '
            NR > 256 { exit }
            $1 == "qdisc" {
                root = ($4 == "root" && $2 ~ /^[a-zA-Z0-9_]+$/ && length($2) <= 16 && $3 ~ /^[a-f0-9]+:$/ && length($3) <= 9)
                if (root) name = device "/" $2 "/" $3
            }
            root && $1 == "Sent" {
                values["bytes"] = $2
                values["packets"] = $4
                for (i = 5; i < NF; i++) {
                    label = $i
                    sub(/^\(/, "", label)
                    if (label == "dropped" || label == "overlimits" || label == "requeues") {
                        value = $(i+1)
                        sub(/[,)]$/, "", value)
                        values[label] = value
                    }
                }
            }
            root && $1 == "backlog" {
                if ($2 ~ /^[0-9]+b$/) values["backlog_bytes"] = substr($2, 1, length($2)-1)
                if ($3 ~ /^[0-9]+p$/) values["backlog_packets"] = substr($3, 1, length($3)-1)
            }
            $0 == "FLR_QDISC_DONE" {
                for (metric in values) printf "qdisc\t%s\t%s\t%s\t%s\n", name, metric, values[metric], (metric ~ /^backlog_/) ? "gauge" : "counter"
                exit
            }'
}

snapshot() {
    wall=$(date -u +%s 2>/dev/null) || wall=
    printf 'sample\t-\twall_epoch_seconds\t%s\tcounter\n' "$wall"
    awk 'NR == 1 {
        if ($1 ~ /^[0-9]+\.[0-9][0-9]$/) { gsub(/\./, "", $1); printf "sample\t-\tuptime_centiseconds\t%s\tcounter\n", $1 }
        exit
    }' "$proc/uptime"
    awk '
        BEGIN { split("user nice system idle iowait irq softirq steal", metrics, " ") }
        NR > 512 { exit }
        $1 ~ /^cpu[0-9]+$/ && length($1) <= 10 {
            if (++cpu > 64) { print "sample\t-\tcpu_limit_reached\t1\tgauge"; exit }
            for (i=1; i<=8 && i<NF; i++) printf "cpu\t%s\t%s\t%s\tcounter\n", $1, metrics[i], $(i+1)
        }
    ' "$proc/stat"
    awk -v targets="$devices" '
        BEGIN {
            count = split(targets, devices, " ")
            for (i=1; i<=count; i++) selected[devices[i]]=1
            split("bytes packets errors dropped", metrics, " ")
        }
        NR > 4096 { exit }
        {
            name = $0
            sub(/:.*/, "", name)
            gsub(/[[:space:]]/, "", name)
            if (!(name in selected) || index($0, ":") == 0) next
            payload = substr($0, index($0, ":")+1)
            sub(/^[[:space:]]+/, "", payload)
            if (split(payload, stats, /[[:space:]]+/) < 16) next
            present[name] = 1
            for (i=1; i<=4; i++) {
                printf "link\t%s\trx_%s\t%s\tcounter\n", name, metrics[i], stats[i]
                printf "link\t%s\ttx_%s\t%s\tcounter\n", name, metrics[i], stats[i+8]
            }
        }
        END {
            for (i=1; i<=count; i++) printf "link\t%s\tpresent\t%d\tgauge\n", devices[i], present[devices[i]]
        }
    ' "$proc/net/dev"
    if [ -r "$proc/net/snmp" ]; then
        awk '
            NR > 128 { exit }
            $1 == "Ip:" || $1 == "Tcp:" || $1 == "Udp:" {
                group = tolower(substr($1, 1, length($1)-1))
                if ($2 ~ /^[a-zA-Z]/) {
                    for (i in fields) delete fields[i]
                    for (i=2; i<=NF && i<=128; i++) fields[i] = $i
                    previous = group
                } else if (previous == group) {
                    for (i in fields) {
                        field = fields[i]
                        if ((group == "ip" && field ~ /^(FragOKs|FragFails|FragCreates|ReasmReqds|ReasmFails)$/) ||
                            (group == "tcp" && field ~ /^(OutSegs|RetransSegs)$/) ||
                            (group == "udp" && field ~ /^(InDatagrams|OutDatagrams|InErrors|RcvbufErrors|SndbufErrors|NoPorts|InCsumErrors)$/))
                            printf "%s\t-\t%s\t%s\tcounter\n", group, field, $i
                    }
                    previous = ""
                }
            }
        ' "$proc/net/snmp"
    fi
    for device in $devices; do
        if IFS= read -r index 2>/dev/null < "$net/$device/ifindex"; then
            printf 'link\t%s\tifindex\t%s\tgauge\n' "$device" "$index"
            if command -v tc >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
                qdisc_snapshot "$device"
            fi
        fi
    done
}

start=$(snapshot)
sleep "$seconds"
finish=$(snapshot)

printf '%s\nFLR_SECOND_SNAPSHOT\n%s\n' "$start" "$finish" | awk -F '\t' '
    # Keep decimal strings intact. BusyBox awk numbers cannot represent all
    # 64-bit counters, so compare lexically and subtract one digit at a time.
    function less(a, b) {
        return length(a) != length(b) ? length(a) < length(b) : "x" a < "x" b
    }
    function delta(a, b, i, j, digit, borrow, result) {
        if (a == "" || b == "" || less(b, a)) return "-"
        j = length(a)
        for (i=length(b); i>0; i--) {
            digit = substr(b, i, 1) - borrow - (j ? substr(a, j--, 1) : 0)
            borrow = (digit < 0)
            result = (digit + 10 * borrow) result
        }
        sub(/^0+/, "", result)
        return result == "" ? "0" : result
    }
    function changed_device(name, key, a, b) {
        sub(/\/.*/, "", name)
        key = "link\t" name "\tifindex"
        return (key in before || key in after) && before[key] != after[key]
    }
    $0 == "FLR_SECOND_SNAPSHOT" { second = 1; next }
    NF == 5 && $4 ~ /^[0-9]+$/ && length($4) <= 20 {
        key = $1 "\t" $2 "\t" $3
        value = $4
        sub(/^0+/, "", value)
        if (value == "") value = "0"
        if (!(key in kind)) keys[++count] = key
        kind[key] = $5
        if (second) after[key] = value
        else before[key] = value
    }
    END {
        clock = "sample\t-\tuptime_centiseconds"
        reboot = (clock in before && clock in after && less(after[clock], before[clock]))
        print "group\tname\tmetric\tbefore\tafter\tdelta"
        for (i=1; i<=count; i++) {
            key = keys[i]
            split(key, fields, "\t")
            a = key in before ? before[key] : "-"
            b = key in after ? after[key] : "-"
            reset = (fields[1] == "link" || fields[1] == "qdisc") && changed_device(fields[2])
            change = (a == "-" || b == "-" || kind[key] != "counter" || reboot || reset) ? "-" : delta(a, b)
            printf "%s\t%s\t%s\t%s\n", key, a, b, change
        }
    }
'
