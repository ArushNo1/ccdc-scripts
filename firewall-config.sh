#!/bin/sh

# Discover expected services and write a separate script that applies the
# resulting inbound firewall policy.

WARN_FILE=
TMP_DIR=
OUT_FILE=
WARNING_COUNT=0

finish_summary() {
    result=${1:-completed}
    if [ "$WARNING_COUNT" -eq 0 ]; then
        echo "Summary: $result with no warnings."
    else
        echo "Summary: $result with $WARNING_COUNT warning(s)."
        while IFS= read -r warning_line; do
            [ -n "$warning_line" ] && echo "$warning_line"
        done < "$WARN_FILE"
    fi
}

cleanup() {
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}

warning() {
    echo "WARNING: $*"
    WARNING_COUNT=$((WARNING_COUNT + 1))
    [ -n "$WARN_FILE" ] && echo "WARNING: $*" >> "$WARN_FILE"
}

fatal() {
    echo "ERROR: $*" >&2
    finish_summary failed
    exit 1
}

if [ "$(id -u 2>/dev/null)" != 0 ]; then
    echo "ERROR: sudo is required; run this script as root." >&2
    echo "Summary: failed."
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "ERROR: supply one or more port,protocol,service arguments." >&2
    echo "Example: sudo ./firewall-config.sh 80,tcp,http 53,udp,dns" >&2
    echo "Summary: failed."
    exit 1
fi

TMP_BASE=${TMPDIR:-/tmp}
TMP_DIR="$TMP_BASE/firewall-config.$$"
if ! (umask 077 && mkdir "$TMP_DIR") 2>/dev/null; then
    echo "ERROR: could not create a private temporary directory." >&2
    echo "Summary: failed."
    exit 1
fi
WARN_FILE="$TMP_DIR/warnings"
EXPECTED_FILE="$TMP_DIR/expected"
SOCKET_FILE="$TMP_DIR/sockets"
MATCH_FILE="$TMP_DIR/matches"
ALLOW_FILE="$TMP_DIR/allow"
: > "$WARN_FILE"
: > "$EXPECTED_FILE"
: > "$SOCKET_FILE"
: > "$MATCH_FILE"
: > "$ALLOW_FILE"
: > "$TMP_DIR/moves"
trap cleanup 0
trap 'exit 1' HUP INT TERM

echo "INFO: capturing the current firewall configuration for the generated rules.sh."
HAVE_V4_SAVE=0
HAVE_V6_SAVE=0
if command -v iptables-save >/dev/null 2>&1; then
    if iptables-save > "$TMP_DIR/ipv4.rules" 2>/dev/null; then
        HAVE_V4_SAVE=1
    else
        warning "could not save IPv4 firewall rules with iptables-save."
    fi
else
    warning "iptables-save is unavailable; install the iptables utilities to back up IPv4 rules."
fi
if command -v ip6tables-save >/dev/null 2>&1; then
    if ip6tables-save > "$TMP_DIR/ipv6.rules" 2>/dev/null; then
        HAVE_V6_SAVE=1
    else
        warning "could not save IPv6 firewall rules with ip6tables-save."
    fi
else
    warning "ip6tables-save is unavailable; install the IPv6 iptables utilities to back up IPv6 rules."
fi
if [ "$HAVE_V4_SAVE" -ne 1 ] || [ "$HAVE_V6_SAVE" -ne 1 ]; then
    fatal "could not back up both IPv4 and IPv6 rules; refusing to generate a script that flushes firewall state."
fi

for argument do
    case "$argument" in
        *,*,*) ;;
        *) fatal "invalid argument '$argument'; expected port,protocol,service." ;;
    esac
    PORT=${argument%%,*}
    REST=${argument#*,}
    PROTOCOL=${REST%%,*}
    SERVICE=${REST#*,}
    case "$SERVICE" in
        *,*) fatal "invalid argument '$argument'; service names cannot contain commas." ;;
    esac
    case "$PORT" in
        ''|*[!0-9]*) fatal "invalid port in '$argument'; use a number from 1 to 65535." ;;
    esac
    if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        fatal "invalid port in '$argument'; use a number from 1 to 65535."
    fi
    case "$PROTOCOL" in
        tcp|udp) ;;
        *) fatal "invalid protocol in '$argument'; protocol must be tcp or udp." ;;
    esac
    [ -n "$SERVICE" ] || fatal "invalid argument '$argument'; service cannot be empty."
    SERVICE_LOWER=$(printf '%s' "$SERVICE" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
    printf '%s|%s|%s|%s\n' "$SERVICE" "$SERVICE_LOWER" "$PROTOCOL" "$PORT" >> "$EXPECTED_FILE"
done

socket_source=
if command -v ss >/dev/null 2>&1; then
    if ss -lntup > "$TMP_DIR/ss.out" 2>/dev/null; then
        socket_source=ss
    fi
fi
if [ "$socket_source" = ss ]; then
    echo "INFO: discovering listeners with ss."
    awk '
        function private4(a, n, x, y, z, w) {
            if (a == "0.0.0.0") return 1
            n = split(a, x, ".")
            if (n != 4) return 0
            for (i = 1; i <= 4; i++) if (x[i] !~ /^[0-9][0-9]*$/ || x[i] > 255) return 0
            if (x[1] == 10) return 1
            if (x[1] == 172 && x[2] >= 16 && x[2] <= 31) return 1
            if (x[1] == 192 && x[2] == 168) return 1
            return 0
        }
        {
            proto = tolower($1)
            state = toupper($2)
            if (proto != "tcp" && proto != "udp") next
            if (proto == "tcp" && state != "LISTEN") next
            local = $5
            if (local !~ /:/) next
            port = local
            sub(/^.*:/, "", port)
            address = local
            sub(/:[^:]*$/, "", address)
            gsub(/^\[/, "", address)
            gsub(/\]$/, "", address)
            sub(/%.*$/, "", address)
            if (!private4(address)) next
            pid = ""
            for (i = 6; i <= NF; i++) {
                if ($i ~ /pid=[0-9]/) {
                    pid = $i
                    sub(/^.*pid=/, "", pid)
                    sub(/[^0-9].*$/, "", pid)
                    break
                }
            }
            if (port ~ /^[0-9]+$/ && pid != "") print proto "|" port "|" address "|" pid
        }
    ' "$TMP_DIR/ss.out" > "$TMP_DIR/raw"
else
    if ! command -v netstat >/dev/null 2>&1; then
        fatal "neither ss nor netstat is available; install iproute2 (ss) or net-tools (netstat)."
    fi
    warning "ss is unavailable or failed; using netstat. Install iproute2 for preferred socket discovery."
    echo "INFO: discovering listeners with netstat."
    if ! netstat -lnptu > "$TMP_DIR/netstat.out" 2>/dev/null; then
        fatal "netstat could not list listening sockets."
    fi
    awk '
        function private4(a, n, x) {
            if (a == "0.0.0.0") return 1
            n = split(a, x, ".")
            if (n != 4) return 0
            for (i = 1; i <= 4; i++) if (x[i] !~ /^[0-9][0-9]*$/ || x[i] > 255) return 0
            if (x[1] == 10) return 1
            if (x[1] == 172 && x[2] >= 16 && x[2] <= 31) return 1
            if (x[1] == 192 && x[2] == 168) return 1
            return 0
        }
        {
            proto = tolower($1)
            if (proto != "tcp" && proto != "udp") next
            if (proto == "tcp" && toupper($6) != "LISTEN") next
            local = $4
            if (local !~ /:/ || local ~ /^\[/) next
            port = local
            sub(/^.*:/, "", port)
            address = local
            sub(/:[^:]*$/, "", address)
            if (!private4(address)) next
            pid = $6
            if (proto == "tcp") pid = $7
            sub(/\/.*/, "", pid)
            if (port ~ /^[0-9]+$/ && pid ~ /^[0-9]+$/) print proto "|" port "|" address "|" pid
        }
    ' "$TMP_DIR/netstat.out" > "$TMP_DIR/raw"
fi

# Use socket owners from the kernel listing, then identify each process from
# /proc instead of assuming a fixed set of daemon names.
while IFS='|' read -r protocol port address pid; do
    [ -n "$pid" ] || continue
    process_name=
    if command -v readlink >/dev/null 2>&1; then
        process_name=$(readlink "/proc/$pid/exe" 2>/dev/null)
        process_name=${process_name##*/}
    fi
    if [ -z "$process_name" ] && [ -r "/proc/$pid/comm" ]; then
        IFS= read -r process_name < "/proc/$pid/comm"
    fi
    [ -n "$process_name" ] || continue
    process_lower=$(printf '%s' "$process_name" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
    printf '%s|%s|%s|%s|%s|%s\n' "$protocol" "$port" "$address" "$pid" "$process_name" "$process_lower" >> "$SOCKET_FILE"
done < "$TMP_DIR/raw"

if [ ! -s "$SOCKET_FILE" ]; then
    warning "no owner-identifiable listeners were found on RFC1918 IPv4 addresses."
fi

awk -F'|' '!seen[$2]++ { print $1 "|" $2 }' "$EXPECTED_FILE" > "$TMP_DIR/services"
while IFS='|' read -r service service_lower; do
    [ -n "$service_lower" ] || continue
    echo "INFO: checking service $service."
    : > "$TMP_DIR/this-service"
    awk -F'|' -v s="$service_lower" '$2 == s { print $3 "|" $4 }' "$EXPECTED_FILE" | sort -u > "$TMP_DIR/this-expected"
    while IFS='|' read -r actual_proto actual_port address pid process_name process_lower; do
        [ -n "$process_lower" ] || continue
        if printf '%s\n' "$process_lower" | grep -F -e "$service_lower" >/dev/null 2>&1; then
            printf '%s|%s|%s|%s\n' "$actual_proto" "$actual_port" "$address" "$process_name" >> "$TMP_DIR/this-service"
        fi
    done < "$SOCKET_FILE"
    if [ ! -s "$TMP_DIR/this-service" ]; then
        echo "ERROR: $service: no matching listener was found on an RFC1918 address."
        finish_summary failed
        exit 1
    fi

    awk -F'|' '{ print $1 }' "$TMP_DIR/this-expected" | sort -u > "$TMP_DIR/expected-protocols"
    awk -F'|' '{ print $1 }' "$TMP_DIR/this-service" | sort -u > "$TMP_DIR/actual-protocols"
    if ! cmp -s "$TMP_DIR/expected-protocols" "$TMP_DIR/actual-protocols"; then
        echo "ERROR: $service: expected protocol set does not match the discovered listeners."
        echo "  Expected: $(tr '\n' ' ' < "$TMP_DIR/expected-protocols")"
        echo "  Found: $(tr '\n' ' ' < "$TMP_DIR/actual-protocols")"
        finish_summary failed
        exit 1
    fi

    expected_total=0
    actual_total=0
    count_mismatch=0
    while IFS= read -r protocol; do
        [ -n "$protocol" ] || continue
        expected_ports=$(awk -F'|' -v p="$protocol" '$1 == p { print $2 }' "$TMP_DIR/this-expected" | sort -n)
        actual_ports=$(awk -F'|' -v p="$protocol" '$1 == p { seen[$2] = 1 } END { for (port in seen) print port }' "$TMP_DIR/this-service" | sort -n)
        expected_count=$(printf '%s\n' "$expected_ports" | awk 'NF { n++ } END { print n+0 }')
        actual_count=$(printf '%s\n' "$actual_ports" | awk 'NF { n++ } END { print n+0 }')
        expected_total=$((expected_total + expected_count))
        actual_total=$((actual_total + actual_count))
        [ "$expected_count" -eq "$actual_count" ] || count_mismatch=1
        if [ "$expected_count" -gt "$actual_count" ]; then
            echo "ERROR: $service: expected $expected_count $protocol port(s), found $actual_count."
            finish_summary failed
            exit 1
        fi
        moved=0
        for port in $expected_ports; do
            case " $actual_ports " in
                *" $port "*) ;;
                *) moved=1 ;;
            esac
        done
        if [ "$moved" -eq 1 ]; then
            warning "$service: expected $protocol port(s) $expected_ports; found $actual_ports."
            printf '%s: %s port(s) moved from %s to %s\n' "$service" "$protocol" "$expected_ports" "$actual_ports" >> "$TMP_DIR/moves"
        else
            echo "INFO: $service: expected $protocol listener(s) located on $actual_ports."
        fi
    done < "$TMP_DIR/expected-protocols"
    if [ "$actual_total" -eq "$expected_total" ] && [ "$count_mismatch" -eq 1 ]; then
        echo "ERROR: $service: the protocol counts changed while the total listener count stayed the same."
        finish_summary failed
        exit 1
    fi
    if [ "$actual_total" -gt "$expected_total" ]; then
        warning "$service: found $actual_total listener(s), more than the $expected_total assumed; using discovered listeners."
        printf '%s: discovered %s listener(s), compared with %s assumed\n' "$service" "$actual_total" "$expected_total" >> "$TMP_DIR/moves"
    fi
    while IFS='|' read -r actual_proto actual_port address process_name; do
        printf '%s|%s|%s\n' "$actual_proto" "$actual_port" "$address" >> "$ALLOW_FILE"
        printf '%s|%s|%s|%s|%s\n' "$service" "$actual_proto" "$actual_port" "$address" "$process_name" >> "$MATCH_FILE"
    done < "$TMP_DIR/this-service"
done < "$TMP_DIR/services"

# Report distinct RFC1918 listeners that did not match any requested service.
while IFS='|' read -r protocol port address pid process_name process_lower; do
    [ -n "$process_lower" ] || continue
    matched=0
    while IFS='|' read -r service service_lower expected_proto expected_port; do
        [ -n "$service_lower" ] || continue
        if [ "$protocol" = "$expected_proto" ] && printf '%s\n' "$process_lower" | grep -F -e "$service_lower" >/dev/null 2>&1; then
            matched=1
            break
        fi
    done < "$EXPECTED_FILE"
    if [ "$matched" -eq 0 ]; then
        warning "unmatched listener: $process_name on $address:$port/$protocol; it will not be allowed."
    fi
done < "$SOCKET_FILE"

if [ ! -s "$ALLOW_FILE" ]; then
    fatal "no ports were selected for the inbound allowlist."
fi
sort -u "$ALLOW_FILE" -o "$TMP_DIR/allow.sorted" 2>/dev/null || sort -u "$ALLOW_FILE" > "$TMP_DIR/allow.sorted"

OUT_FILE=rules.sh
OUT_SUFFIX=1
while [ -e "$OUT_FILE" ]; do
    OUT_FILE="rules.sh.$OUT_SUFFIX"
    OUT_SUFFIX=$((OUT_SUFFIX + 1))
done

RULE_DIR=$(CDPATH= cd "$(dirname "$OUT_FILE")" 2>/dev/null && pwd -P)
[ -n "$RULE_DIR" ] || RULE_DIR=.
MARKER="$RULE_DIR/.rules-login-confirmed"

cat > "$OUT_FILE" <<EOF
#!/bin/sh
# Generated by firewall-config.sh. Review before running.
# Confirm a fresh remote login within 120 seconds by creating:
#   sudo touch $MARKER-<rules.sh-process-id>

set -u
MARKER='$MARKER-'\$\$

if [ "\$(id -u 2>/dev/null)" != 0 ]; then
    echo "ERROR: sudo is required; run this script as root." >&2
    exit 1
fi
for command_name in iptables ip6tables iptables-restore ip6tables-restore; do
    if ! command -v "\$command_name" >/dev/null 2>&1; then
        echo "ERROR: required command \$command_name is unavailable." >&2
        exit 1
    fi
done
restore_ipv4() {
    iptables-restore <<'FIREWALL_CONFIG_IPV4_SNAPSHOT'
EOF
cat "$TMP_DIR/ipv4.rules" >> "$OUT_FILE"
cat >> "$OUT_FILE" <<'EOF'
FIREWALL_CONFIG_IPV4_SNAPSHOT
}

restore_ipv6() {
    ip6tables-restore <<'FIREWALL_CONFIG_IPV6_SNAPSHOT'
EOF
cat "$TMP_DIR/ipv6.rules" >> "$OUT_FILE"
cat >> "$OUT_FILE" <<'EOF'
FIREWALL_CONFIG_IPV6_SNAPSHOT
}

restore_firewall() {
    restore_ipv4 2>/dev/null
    restore_ipv6 2>/dev/null
}

(
    sleep 120
    if [ ! -f "\$MARKER" ]; then
        echo "WARNING: login was not confirmed; restoring saved firewall rules." >&2
        restore_firewall
        echo "Summary: previous firewall rules restored." >&2
    fi
) &

iptables -F || { restore_firewall; exit 1; }
iptables -X || { restore_firewall; exit 1; }
iptables -Z || { restore_firewall; exit 1; }
ip6tables -F || { restore_firewall; exit 1; }
ip6tables -X || { restore_firewall; exit 1; }
ip6tables -Z || { restore_firewall; exit 1; }
iptables -P INPUT DROP || { restore_firewall; exit 1; }
iptables -P FORWARD DROP || { restore_firewall; exit 1; }
iptables -P OUTPUT ACCEPT || { restore_firewall; exit 1; }
ip6tables -P INPUT DROP || { restore_firewall; exit 1; }
ip6tables -P FORWARD DROP || { restore_firewall; exit 1; }
ip6tables -P OUTPUT ACCEPT || { restore_firewall; exit 1; }
iptables -A INPUT -i lo -j ACCEPT || { restore_firewall; exit 1; }
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || { restore_firewall; exit 1; }
EOF
cat >> "$OUT_FILE" <<'EOF'
while IFS='|' read -r protocol port address; do
    [ -n "$protocol" ] || continue
    if [ "$address" = 0.0.0.0 ]; then
        iptables -A INPUT -p "$protocol" --dport "$port" -m state --state NEW -j ACCEPT || { restore_firewall; exit 1; }
    else
        iptables -A INPUT -d "$address" -p "$protocol" --dport "$port" -m state --state NEW -j ACCEPT || { restore_firewall; exit 1; }
    fi
done <<'ALLOW_RULES'
EOF
while IFS='|' read -r protocol port address; do
    printf '%s|%s|%s\n' "$protocol" "$port" "$address" >> "$OUT_FILE"
done < "$TMP_DIR/allow.sorted"
cat >> "$OUT_FILE" <<'EOF'
ALLOW_RULES

echo "INFO: firewall rules installed. Confirm a fresh remote login, then run: sudo touch $MARKER"
echo "Summary: firewall policy installed; login confirmation is pending."
exit 0
EOF

while IFS= read -r move_line; do
    [ -n "$move_line" ] && printf '# Port change: %s\n' "$move_line" >> "$OUT_FILE"
done < "$TMP_DIR/moves"

chmod 700 "$OUT_FILE"
echo "INFO: generated $OUT_FILE"
echo "INFO: matched listener changes:"
if [ -s "$MATCH_FILE" ]; then
    while IFS='|' read -r service protocol port address process_name; do
        echo "  $service: $process_name on $address:$port/$protocol"
    done < "$MATCH_FILE"
fi
finish_summary
exit 0
