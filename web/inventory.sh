#!/bin/sh
#
# inventory_services.sh - find the websites on this machine and everything they run on.
#
# Finds all listening TCP sockets (on the host and inside containers), works out
# which process owns each one, sends it an HTTP request, and reports the ones that
# are websites: process, container, vhosts, web root, web app, database, and the
# backends a reverse proxy sends traffic to. Listening ports that are not websites
# (databases, Docker, Kubernetes, ...) are left out.
#
# It does not trust process names or web server configs to find a site, so a web
# server that is renamed, hidden or missing from every config still shows up.
#
# Usage: sh inventory_services.sh
#
# Plain POSIX sh: runs under dash, busybox ash, ksh or bash, old or new. No
# arrays or other shell extras, only small temp files, and only tool options
# that old GNU and busybox tools understand.

# The run is cut short after this many seconds, and whatever is done is printed.
# (Tools that run scripts over SSH often kill them after 30-60 seconds.)
budget=25

start=$(date +%s 2>/dev/null)
case $start in
    ''|*[!0-9]*) start=0 ;;    # no "date +%s" here, so no time limit
esac

if [ "$(id -u)" -ne 0 ]; then
    # Try passwordless sudo first; re-exec only when $0 is a real file path.
    # coordinate feeds script lines into -bash so $0 is the shell name; in that
    # case coordinate's -S flag already handles escalation before the script runs.
    case "$0" in -*) ;; *)
        if sudo -n true 2>/dev/null; then exec sudo sh "$0" "$@"; fi ;;
    esac
    is_root=no
    echo "WARNING: not running as root. Processes owned by other users are invisible," >&2
    echo "         so many ports will show no owner and most containers will be missed." >&2
    echo "         Use 'coordinate -S' or run: sudo sh inventory_services.sh" >&2
else
    is_root=yes
fi

# We only talk to localhost, so never go through a configured proxy.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY

# curl is preferred. wget, nc and bash can probe too, but with less detail.
if command -v curl >/dev/null 2>&1; then
    fetcher=curl
elif command -v wget >/dev/null 2>&1; then
    fetcher=wget
    echo "WARNING: curl not found, using wget. Install curl for more reliable probing." >&2
elif command -v nc >/dev/null 2>&1; then
    fetcher=nc
    echo "WARNING: neither curl nor wget found, probing with nc (HTTP only, no HTTPS)." >&2
    echo "         Install curl for more reliable probing." >&2
elif command -v bash >/dev/null 2>&1; then
    fetcher=bash
    echo "WARNING: neither curl, wget nor nc found, probing with bash (HTTP only, no HTTPS)." >&2
    echo "         Install curl for more reliable probing." >&2
else
    fetcher=none
    echo "WARNING: no curl, wget, nc or bash found, so ports are listed but NOT probed." >&2
    echo "         Install curl to see which ports are web services." >&2
fi

if ! command -v nsenter >/dev/null 2>&1; then
    echo "WARNING: nsenter not found (part of util-linux), so ports inside containers" >&2
    echo "         are listed but not probed." >&2
fi

tmp=/tmp/inventory_services.$$
mkdir -m 700 "$tmp" || exit 1
# Kill scan workers and their children before removing their output directory.
cleanup() {
    trap '' HUP INT TERM
    awk -v root="$$" '
        /^Pid:/ { p = $2 }
        /^PPid:/ { parent[p] = $2 }
        END {
            owned[root] = 1
            for (pass = 1; pass <= 20; pass++)
                for (p in parent) if (parent[p] in owned) owned[p] = 1
            for (p in owned) if (p != root) print p
        }' /proc/[0-9]*/status 2>/dev/null > "$tmp/children"
    while read -r child; do kill "$child" 2>/dev/null; done < "$tmp/children"
    wait 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup 0
trap 'exit 1' INT TERM HUP


# --- helpers -------------------------------------------------------------------

if ! command -v readlink >/dev/null 2>&1; then
    echo "WARNING: readlink missing; using ls. Install coreutils for reliable link paths." >&2
    readlink() { ls -ld "$1" 2>/dev/null | sed -n 's/^.* -> //p'; }
fi

field() {
    printf '  %-11s %s\n' "$1" "$2"
}

# same, one level deeper (used under a vhost)
sub_field() {
    printf '    %-10s %s\n' "$1" "$2"
}

# process name, read from /proc/<pid>/status (works on every kernel)
proc_name() {
    if { read -r pn_name < /proc/"$1"/comm; } 2>/dev/null; then
        echo "$pn_name"
    else
        awk '/^Name:/ { print $2 }' /proc/"$1"/status 2>/dev/null
    fi
}

# Runs a command with a time limit. Uses "timeout" when it exists (old systems
# don't have it) and a background kill otherwise.
timeout_style=none
if command -v timeout >/dev/null 2>&1; then
    if timeout 1 sh -c 'exit 0' >/dev/null 2>&1; then timeout_style=plain
    elif timeout -t 1 sh -c 'exit 0' >/dev/null 2>&1; then timeout_style=old
    fi
fi
run_with_timeout() {
    rwt_secs=$1
    shift
    if [ "$timeout_style" = plain ]; then
        timeout "$rwt_secs" "$@"; return
    elif [ "$timeout_style" = old ]; then
        timeout -t "$rwt_secs" "$@"; return
    fi
    "$@" &
    rwt_cmd=$!
    ( sleep "$rwt_secs" & sleeper=$!; trap 'kill "$sleeper" 2>/dev/null; exit' TERM INT HUP; wait "$sleeper"; kill "$rwt_cmd" 2>/dev/null ) >/dev/null 2>&1 &
    rwt_killer=$!
    wait "$rwt_cmd" 2>/dev/null
    rwt_rc=$?
    kill "$rwt_killer" 2>/dev/null
    return $rwt_rc
}

out_of_time() {
    [ "$start" -gt 0 ] || return 1
    oot_now=$(date +%s)
    [ $((oot_now - start)) -ge "$budget" ]
}


# --- 1. find listening sockets in every network namespace ----------------------

# Containers have their own network namespace, so /proc/net/tcp of the host does
# not show their ports. Pick one pid per namespace and read its tables instead.
# (Kernels before 3.0 have no namespaces; then there is just "host".)
host_ns=$(readlink /proc/self/ns/net 2>/dev/null)
[ -n "$host_ns" ] || host_ns=host

# "<namespace> <pid>", one line per namespace, the host first.
# (One "ls -l" for all pids: starting a readlink per pid is slow on busy boxes.)
{
    echo "$host_ns $$"
    ls -l /proc/[0-9]*/ns/net 2>/dev/null |
        awk '$(NF - 1) == "->" { split($(NF - 2), a, "/"); print $NF, a[3] }'
} | awk '!seen[$1]++' > "$tmp/namespaces"

# "<namespace> <address> <port> <inode>", one line per listening socket
# (state 0A = LISTEN). The kernel prints addresses and ports as hex, and the
# address bytes in little-endian order, so they are converted here.
while read -r ns p; do
    cat /proc/"$p"/net/tcp /proc/"$p"/net/tcp6 2>/dev/null |
        awk -v ns="$ns" '
            function hex(s,   i, n) {
                n = 0
                for (i = 1; i <= length(s); i++)
                    n = n * 16 + index("0123456789ABCDEF", toupper(substr(s, i, 1))) - 1
                return n
            }
            # "0100007F" -> 127.0.0.1
            function ip4(h) {
                return hex(substr(h, 7, 2)) "." hex(substr(h, 5, 2)) "." hex(substr(h, 3, 2)) "." hex(substr(h, 1, 2))
            }
            function ip6(h,   i, w, out) {
                if (h ~ /^0+$/) return "::"
                if (h == "00000000000000000000000001000000") return "::1"
                # IPv4 address inside an IPv6 socket (::ffff:a.b.c.d)
                if (substr(h, 1, 16) == "0000000000000000" && substr(h, 17, 8) == "FFFF0000")
                    return ip4(substr(h, 25, 8))
                out = ""
                for (i = 0; i < 4; i++) {
                    w = substr(h, i * 8 + 1, 8)
                    out = out (i ? ":" : "") sprintf("%x:%x", hex(substr(w, 7, 2) substr(w, 5, 2)), hex(substr(w, 3, 2) substr(w, 1, 2)))
                }
                return out
            }
            $4 == "0A" {
                split($2, a, ":")
                print ns, (length(a[1]) == 8 ? ip4(a[1]) : ip6(a[1])), hex(a[2]), $10
            }'
done < "$tmp/namespaces" > "$tmp/listeners"

# Listening unix sockets ("<path> <inode>"), for backends like php-fpm that are
# reached through a socket file instead of a port. State flag 00010000 = listening.
while read -r ns p; do
    awk '$4 == "00010000" && $8 ~ /^\// { print $8, $7 }' /proc/"$p"/net/unix 2>/dev/null
done < "$tmp/namespaces" > "$tmp/unix_listeners"


# --- 2. map each socket to the process that owns it ----------------------------

# A socket shows up as a "socket:[inode]" link in /proc/<pid>/fd. When several
# processes share one (nginx workers) we keep the lowest pid, i.e. the master.
# Result: "<pid> <inode>"
ls -l /proc/[0-9]*/fd 2>/dev/null |
    awk '
        /^\/proc\/[0-9]+\/fd:/ { split($0, a, "/"); pid = a[3] }
        $NF ~ /^socket:\[/     { inode = $NF; gsub(/[^0-9]/, "", inode); print pid, inode }' |
    sort -k2,2 -k1,1n |
    awk '!seen[$2]++' > "$tmp/inode_pid"

# One line per namespace+port (a port on IPv4 and IPv6 counts once), sorted by
# port: "<namespace>|<port>|<address>|<pid>". pid is 0 if no owner was found.
awk '
    FILENAME == ARGV[1] { owner[$2] = $1; next }
    { print $1 "|" $3 "|" $2 "|" (owner[$4] + 0) }' "$tmp/inode_pid" "$tmp/listeners" |
    sort -u |
    sort -t'|' -k2,2n > "$tmp/sites"

# "<path> <pid>" for each listening unix socket
awk '
    FILENAME == ARGV[1] { owner[$2] = $1; next }
    ($2 in owner) { print $1, owner[$2] }' "$tmp/inode_pid" "$tmp/unix_listeners" > "$tmp/unix_owner"

# "<namespace> <port> <process name> (pid N)", used to say what a proxy target
# points at
while IFS='|' read -r ns port addr pid; do
    name=$(proc_name "$pid")
    echo "$ns $port ${name:-?} (pid $pid)"
done < "$tmp/sites" > "$tmp/port_owner"

# "<namespace> <ip address>" for every address of every namespace, to tell which
# container an address belongs to
while read -r ns p; do
    awk -v ns="$ns" '/\|-- / { ip = $2 } /\/32 host LOCAL/ { print ns, ip }' /proc/"$p"/net/fib_trie 2>/dev/null
done < "$tmp/namespaces" | sort -u > "$tmp/ns_ips"

# Docker's userland proxy forwards a published host port into a container. Its
# command line says where: "<container port> <host port> <proxy pid> <container
# ip>". The container's own listener then reports the host port, and the proxy
# itself is not listed as a separate service.
grep ' docker-proxy (pid ' "$tmp/port_owner" |
    sed -n 's/.*(pid \([0-9]*\))$/\1/p' |
    while read -r fp; do
        tr '\0' ' ' < /proc/"$fp"/cmdline 2>/dev/null |
            awk -v pid="$fp" '{
                for (i = 1; i < NF; i++) {
                    if ($i == "-host-port")      h = $(i + 1)
                    if ($i == "-container-port") c = $(i + 1)
                    if ($i == "-container-ip")   a = $(i + 1)
                }
                print c, h, pid, a
            }'
    done | sort -u > "$tmp/forwards"

# Docker's names for its containers: "<name> <ip> <container name>", for the
# container name, its compose service name and every address. A proxy target like
# "admin:8080" uses a compose service name, which only Docker's own DNS can turn
# into an address.
: > "$tmp/docker_names"
if command -v docker >/dev/null 2>&1; then
    dk_ids=$(run_with_timeout 4 docker ps -q 2>/dev/null)
    if [ -n "$dk_ids" ]; then
        run_with_timeout 5 docker inspect --format \
            '{{.Name}} {{index .Config.Labels "com.docker.compose.service"}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
            $dk_ids 2>/dev/null |
            awk '{
                name = $1; sub(/^\//, "", name); svc = ""
                for (i = 2; i <= NF; i++) if ($i !~ /^[0-9.]+$/) svc = $i
                for (i = 2; i <= NF; i++)
                    if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                        print name, $i, name
                        if (svc != "") print svc, $i, name
                    }
            }' > "$tmp/docker_names"
    fi
fi

# --- 2b. ports the firewall forwards ------------------------------------------

# Kubernetes (NodePorts, the k3s load balancer, hostPort) and Docker without its
# proxy publish ports with firewall (NAT) rules only: a rule rewrites the
# destination of the traffic, so no program on this machine owns the port and it
# is in no socket table. Read the rules, follow them to where they send the
# traffic, and probe those ports with this machine's own address.
: > "$tmp/used"          # "<pid> <port> <entry port>": a proxy target that was found
: > "$tmp/entry_pids"    # "<pid> <port>": programs behind an entry point
: > "$tmp/nat_rules"     # "<port> <where it is sent> <kubernetes service>"
: > "$tmp/nat_dest"
: > "$tmp/k8s_pods"
: > "$tmp/k8s_ingress"
kube=
local_ip=$(awk '/\|-- / { ip = $2 } /\/32 host LOCAL/ && ip !~ /^127\./ { print ip; exit }' /proc/net/fib_trie 2>/dev/null)
if [ -n "$local_ip" ]; then
    iptables-save -t nat 2>/dev/null > "$tmp/nat_raw"

    # A rule for a port jumps to other chains (Kubernetes uses three levels:
    # NodePort -> service -> endpoint) until a DNAT rule names the real target.
    # Rules for one specific address (Kubernetes cluster IPs) are left out.
    awk '
        function add(d) {
            if (nfound < 4 && index("," found ",", "," d ",") == 0) {
                found = found (found == "" ? "" : ",") d
                nfound++
            }
        }
        function resolve(chain, port, depth,   k) {
            if (depth > 6) return
            for (k = 1; k <= ndn[chain]; k++)
                if (dn_port[chain, k] == "" || dn_port[chain, k] == port) add(dn_dest[chain, k])
            for (k = 1; k <= njump[chain]; k++) resolve(jump[chain, k], port, depth + 1)
        }
        /^-A / {
            chain = $2; proto = ""; dport = ""; target = ""; dest = ""; one = 0; svc = ""
            for (i = 3; i <= NF; i++) {
                if ($i == "-p") proto = $(i + 1)
                if ($i == "-d" && $(i + 1) ~ /^[0-9]/) one = 1
                if ($i == "--dport" || $i == "--dports") dport = $(i + 1)
                if ($i == "-j") target = $(i + 1)
                if ($i == "--to-destination") dest = $(i + 1)
                if ($i == "--comment") {
                    c = $(i + 1); gsub(/"/, "", c)
                    if (c ~ /^[a-z0-9.-]+\/[A-Za-z0-9._-]+/) svc = c
                }
            }
            if (proto == "udp") next
            if (target == "DNAT" && dest != "") {
                k = ++ndn[chain]; dn_dest[chain, k] = dest; dn_port[chain, k] = dport
            } else if (target != "" && target !~ /^(RETURN|ACCEPT|DROP|REJECT|MASQUERADE|SNAT|LOG|MARK|REDIRECT|KUBE-MARK-[A-Z]+|CNI-HOSTPORT-SETMARK|CNI-HOSTPORT-MASQ)$/) {
                k = ++njump[chain]; jump[chain, k] = target
            }
            if (dport != "" && target != "") {
                n++; r_port[n] = dport; r_target[n] = target; r_dest[n] = dest; r_one[n] = one; r_svc[n] = svc
            }
        }
        END {
            for (k = 1; k <= n; k++) {
                if (r_one[k]) continue
                m = split(r_port[k], pp, ",")
                for (j = 1; j <= m; j++) {
                    if (pp[j] !~ /^[0-9]+$/) continue
                    found = ""; nfound = 0
                    if (r_dest[k] != "") add(r_dest[k]); else resolve(r_target[k], pp[j], 0)
                    print pp[j], (found == "" ? "-" : found), (r_svc[k] == "" ? "-" : r_svc[k])
                }
            }
        }' "$tmp/nat_raw" > "$tmp/nat_rules"

    # Kubernetes can say which pod a rule leads to and which hostnames its ingress
    # serves. Only asked if the rules are Kubernetes ones and kubectl is here.
    if grep -q 'KUBE-' "$tmp/nat_raw"; then
        if command -v kubectl >/dev/null 2>&1; then
            kube=kubectl
        elif command -v k3s >/dev/null 2>&1; then
            kube="k3s kubectl"
        fi
    fi
    if [ -n "$kube" ]; then
        run_with_timeout 5 $kube get pods -A --no-headers \
            -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName \
            > "$tmp/k8s_pods" 2>/dev/null &
        run_with_timeout 5 $kube get ingress -A --no-headers \
            -o 'custom-columns=NS:.metadata.namespace,NAME:.metadata.name,HOSTS:.spec.rules[*].host' \
            > "$tmp/k8s_ingress" 2>/dev/null &
        wait
    fi

    # "<address>:<port>" of every listener inside a container or pod that we can
    # see. A rule that sends traffic to one of those is shown as that container.
    tr '|' ' ' < "$tmp/sites" | awk -v hn="$host_ns" '
        FILENAME == ARGV[1] { ips[$1] = ips[$1] " " $2; next }
        $1 != hn { m = split(ips[$1], a, " "); for (k = 1; k <= m; k++) print a[k] ":" $2 }' \
        "$tmp/ns_ips" - | sort -u > "$tmp/visible"

    # One line per port, with every place the rules send it. A rule overrides a
    # program listening on the same port for traffic from other machines (that is
    # how a k3s node answers on 80 and 443 while something else listens there),
    # so these ports are probed even if a program listens on them. A port whose
    # targets are all containers we already report is left out.
    awk '
        FILENAME == ARGV[1] { vis[$1] = 1; next }
        {
            if (!($1 in dst)) { order[++no] = $1; dst[$1] = ""; svc[$1] = "-" }
            if ($2 != "-") {
                m = split($2, ds, ",")
                for (k = 1; k <= m; k++)
                    if (index("," dst[$1] ",", "," ds[k] ",") == 0)
                        dst[$1] = dst[$1] (dst[$1] == "" ? "" : ",") ds[k]
            }
            if ($3 != "-" && svc[$1] == "-") svc[$1] = $3
        }
        END {
            for (k = 1; k <= no; k++) {
                p = order[k]
                m = split(dst[p], ds, ",")
                all = (dst[p] != "")
                for (j = 1; j <= m; j++) if (!(ds[j] in vis)) all = 0
                if (!all) print p, (dst[p] == "" ? "-" : dst[p]), svc[p]
            }
        }' "$tmp/visible" "$tmp/nat_rules" > "$tmp/nat_dest"

    # The usual web ports, when nothing listens there and no rule mentions them
    # (some firewalls forward without showing it here).
    awk -F'|' -v hn="$host_ns" '$1 == hn { print $2 }' "$tmp/sites" > "$tmp/host_ports"
    for guess in 80 443 8080 8443; do
        if ! grep -q "^$guess " "$tmp/nat_rules" && ! grep -qx "$guess" "$tmp/host_ports"; then
            echo "$guess - -" >> "$tmp/nat_dest"
        fi
    done
    head -n 30 "$tmp/nat_dest" > "$tmp/nat_dest.cut"
    mv "$tmp/nat_dest.cut" "$tmp/nat_dest"
    awk -v ip="$local_ip" '{ print "nat|" $1 "|" ip "|0" }' "$tmp/nat_dest" >> "$tmp/sites"
    sort -t'|' -k2,2n -o "$tmp/sites" "$tmp/sites"
fi

# Which process listens on a port? Prints "name (pid N)".
# $1 = port, $2 = namespace the asker lives in, $3 = "any" to also look in the
# host and in other namespaces (for targets such as "app:8000" that may be a
# different container). Without it only the asker's own namespace counts, which
# is right for 127.0.0.1 targets.
who_listens() {
    awk -v p="$1" -v ns="$2" -v hn="$host_ns" -v mode="$3" '
        $2 == p {
            rest = $0
            sub(/^[^ ]+ [^ ]+ /, "", rest)
            if ($1 == ns) { print rest; found = 1; exit }
            if ($1 == hn && !host) host = rest
            if (!other) other = rest
        }
        END {
            if (!found && mode == "any") print (host ? host : other)
        }' "$tmp/port_owner"
}

# Remembers that a proxy sends traffic to a program ($1 = "name (pid N)" as
# who_listens prints it, $2 = its port), so it can be shown as "used by port ..."
record_use() {
    ru_pid=$(printf '%s' "$1" | sed -n 's/.*(pid \([0-9]*\)).*/\1/p')
    [ -n "$ru_pid" ] && echo "$ru_pid $2 ${entry_label:-?}" >> "$tmp/used"
}

# Says where a proxy/backend/database target points. Targets look like
# "http://127.0.0.1:8081/app", "127.0.0.1:9000", "http://admin:8080",
# "unix:/run/php/fpm.sock" or "proxy:unix:/run/x.sock|fcgi://localhost". Prints
# nothing if it can't tell.
# $1 = target, $2 = namespace of the process that uses it
target_owner() {
    to_t=$1
    case $to_t in
        *unix:*)
            to_path=${to_t#*unix:}
            to_path=${to_path%%[|:]*}
            # /var/run is usually a link to /run, and the kernel lists the real one
            case $to_path in
                /var/run/*) to_alt=/run/${to_path#/var/run/} ;;
                /run/*)     to_alt=/var/run/${to_path#/run/} ;;
                *)          to_alt=$to_path ;;
            esac
            to_pid=$(awk -v p="$to_path" -v q="$to_alt" '$1 == p || $1 == q { print $2; exit }' "$tmp/unix_owner")
            if [ -n "$to_pid" ]; then
                echo "$(proc_name "$to_pid") (pid $to_pid)"
            else
                echo "nothing listening on $to_path"
            fi
            return ;;
    esac
    to_scheme=
    case $to_t in
        *://*) to_scheme=${to_t%%://*} ;;
    esac
    to_t=${to_t#*://}
    to_t=${to_t%%/*}
    # "http://webmail" means port 80
    case $to_t in
        *:*|*[!A-Za-z0-9.-]*|'') ;;
        *) case $to_scheme in
               http)  to_t=$to_t:80 ;;
               https) to_t=$to_t:443 ;;
           esac ;;
    esac
    to_port=${to_t##*:}
    case $to_port in
        ''|*[!0-9]*) return ;;     # no port in it (an upstream name, a balancer, ...)
    esac
    to_host=${to_t%:*}
    case $to_host in
        127.*|localhost|'[::1]'|0.0.0.0|'[::]')
            to_who=$(who_listens "$to_port" "$2")
            if [ -n "$to_who" ]; then
                record_use "$to_who" "$to_port"
                echo "$to_who"
            else
                echo "nothing listening on port $to_port"
            fi ;;
        *)
            # a Docker container name or compose service name, or an address
            to_ip=$(awk -v h="$to_host" '$1 == h { print $2; exit }' "$tmp/docker_names")
            case $to_host in
                [0-9]*.[0-9]*.[0-9]*.[0-9]*) to_ip=$to_host ;;
            esac
            to_ns=
            [ -n "$to_ip" ] && to_ns=$(awk -v ip="$to_ip" '$2 == ip { print $1; exit }' "$tmp/ns_ips")
            if [ -n "$to_ns" ]; then
                to_cn=$(awk -v ip="$to_ip" '$2 == ip { print $3; exit }' "$tmp/docker_names")
                to_where=
                [ -n "$to_cn" ] && [ "$to_ns" != "$host_ns" ] && to_where="  (container $to_cn)"
                to_who=$(who_listens "$to_port" "$to_ns")
                if [ -n "$to_who" ]; then
                    record_use "$to_who" "$to_port"
                    echo "$to_who$to_where"
                else
                    echo "nothing listening on port $to_port$to_where"
                fi
            else
                case $to_host in
                    [0-9]*.[0-9]*.[0-9]*.[0-9]*)
                        echo "address $to_host is not on this machine" ;;
                    *)
                        to_who=$(who_listens "$to_port" "$2" any)
                        if [ -n "$to_who" ]; then
                            record_use "$to_who" "$to_port"
                            echo "$to_who  (host $to_host: a program on this port here, or another machine?)"
                        else
                            echo "host $to_host is not a running container here (stopped, or another machine)"
                        fi ;;
                esac
            fi ;;
    esac
}

bind_address() {
    case $1 in
        0.0.0.0|::) echo "all interfaces" ;;
        127.*|::1)  echo "localhost only" ;;
        *)          echo "$1 only" ;;
    esac
}


# Name of the Docker container whose network namespace this is (empty if none)
ns_container_name() {
    awk -v n="$1" '
        FILENAME == ARGV[1] { if ($1 == n) mine[$2] = 1; next }
        $2 in mine { print $3; exit }' "$tmp/ns_ips" "$tmp/docker_names"
}

# The host ports that lead to port $2 of namespace $1, one per line:
# "<host port> <how>". Docker's userland proxy and firewall rules both do this.
published_ports() {
    awk -v ns="$1" -v p="$2" '
        FILENAME == ARGV[1] { if ($1 == ns) mine[$2] = 1; next }
        FILENAME == ARGV[2] {
            if ($1 == p && ($4 == "" || ($4 in mine)) && !($2 in seen)) {
                seen[$2] = 1
                print $2, "docker-proxy, pid " $3
            }
            next
        }
        {
            n = split($2, ds, ",")
            for (k = 1; k <= n; k++) {
                ip = ds[k]; q = ds[k]
                sub(/:[0-9]+$/, "", ip); sub(/^.*:/, "", q)
                if (q == p && (ip in mine) && !($1 in seen)) {
                    seen[$1] = 1
                    print $1, "firewall rule"
                }
            }
        }' "$tmp/ns_ips" "$tmp/forwards" "$tmp/nat_rules"
}


# --- 3. probe a port over HTTP -------------------------------------------------

# Splits a raw HTTP response in $pr_dir/raw into $pr_dir/headers and $pr_dir/body.
split_raw() {
    tr -d '\r' < "$pr_dir/raw" > "$pr_dir/raw_clean"
    sed -n '1,/^$/p' "$pr_dir/raw_clean" > "$pr_dir/headers"
    sed '1,/^$/d' "$pr_dir/raw_clean" > "$pr_dir/body"
}

# Checks whether a port speaks TLS by sending a minimal TLS 1.0 ClientHello and
# looking at the first byte of the reply: 0x16 (handshake) or 0x15 (alert) means
# TLS, even if the server then refuses us. Needs nc or bash. Uses $in_ns.
# $1 = host, $2 = port
speaks_tls() {
    tls_hello='\026\003\001\000\061\001\000\000\055\003\001'
    tls_hello="$tls_hello"'\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000'
    tls_hello="$tls_hello"'\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000'
    tls_hello="$tls_hello"'\000\000\006\000\057\000\065\000\012\001\000'
    if command -v nc >/dev/null 2>&1; then
        # some versions of nc never give up on a silent port, so use timeout if we can
        tls_limit=
        [ "$timeout_style" = plain ] && tls_limit="timeout 3"
        [ "$timeout_style" = old ] && tls_limit="timeout -t 3"
        tls_first=$(printf "$tls_hello" | $tls_limit $in_ns nc -w 2 "$1" "$2" 2>/dev/null |
            od -An -tx1 -N1 2>/dev/null | tr -d ' \n')
    elif command -v bash >/dev/null 2>&1; then
        tls_first=$(run_with_timeout 2 $in_ns bash -c \
            'exec 3<>/dev/tcp/$0/$1; printf "$2" >&3; dd bs=1 count=1 <&3 2>/dev/null' "$1" "$2" "$tls_hello" 2>/dev/null |
            od -An -tx1 -N1 2>/dev/null | tr -d ' \n')
    else
        return 1
    fi
    case $tls_first in
        15|16) return 0 ;;
    esac
    return 1
}

# Sends a request to the address a port is bound to (127.0.0.1 for "all
# interfaces"), inside the socket's namespace, and sets http_status, http_server
# and http_title. http_status stays empty if nothing answered with HTTP.
# Several probes run at the same time, so each one works in its own directory.
probe_net() {
    pr_id=$1
    pr_pid=$2
    pr_ns=$3
    pr_port=$4
    pr_addr=$5
    pr_dir=$tmp/probe.$pr_id
    mkdir -p "$pr_dir"
    in_ns=
    http_status=
    http_server=
    http_title=
    http_login=
    pr_plain=
    pr_plain_server=
    pr_plain_title=

    if [ "$fetcher" = none ]; then
        http_status="(not probed, no curl/wget/nc/bash available)"
        return
    fi
    if [ "$pr_ns" != "$host_ns" ]; then
        if ! command -v nsenter >/dev/null 2>&1; then
            http_status="(not probed, nsenter is not installed)"
            return
        fi
        in_ns="nsenter -t $pr_pid -n"
    fi

    # A socket bound to one address does not answer on 127.0.0.1, so connect to
    # the address it is bound to. "::" may be IPv6-only, so try IPv6 localhost too.
    case $pr_addr in
        0.0.0.0) pr_hosts=127.0.0.1 ;;
        ::)      pr_hosts="127.0.0.1 ::1" ;;
        *)       pr_hosts=$pr_addr ;;
    esac

    pr_rc=0
    pr_https_rc=0
    pr_silent=no
    pr_tls=
    pr_sni=$(hostname 2>/dev/null)
    [ -n "$pr_sni" ] || pr_sni=localhost
    for pr_host in $pr_hosts; do
        pr_url_host=$pr_host
        case $pr_host in
            *:*) pr_url_host="[$pr_host]" ;;    # IPv6 addresses need brackets in a URL
        esac

        for pr_scheme in http https; do
            pr_variants=plain
            if [ "$pr_scheme" = https ]; then
                case $fetcher in
                    curl) pr_variants="plain legacy sni" ;;  # old TLS versions/ciphers; a server name
                    wget) pr_variants=plain ;;
                    *)    continue ;;                    # nc and bash can't do TLS
                esac
            fi

            for pr_variant in $pr_variants; do
                # Old TLS settings are only worth a retry if the normal handshake
                # failed (curl exit 35). A timeout would just time out again.
                # Only worth it if the port really speaks TLS (many non-web services
                # reject our hello with the same exit code).
                if [ "$pr_variant" = plain ]; then
                    pr_url="$pr_scheme://$pr_url_host:$pr_port/"
                else
                    [ "$pr_https_rc" -eq 35 ] || continue
                    [ -n "$pr_tls" ] || { speaks_tls "$pr_host" "$pr_port" && pr_tls=yes || pr_tls=no; }
                    [ "$pr_tls" = yes ] || continue
                fi
                : > "$pr_dir/headers"
                : > "$pr_dir/body"
                case $fetcher in
                    curl)
                        pr_extra=
                        if [ "$pr_variant" = legacy ]; then
                            pr_extra="--tlsv1.0 --ciphers DEFAULT:@SECLEVEL=0"
                        elif [ "$pr_variant" = sni ]; then
                            # some servers refuse a handshake without a server name
                            pr_extra="--resolve $pr_sni:$pr_port:$pr_host"
                            pr_url="https://$pr_sni:$pr_port/"
                        fi
                        $in_ns curl -sk -g $pr_extra --connect-timeout 2 -m 3 -D "$pr_dir/headers" -o "$pr_dir/body" \
                            "$pr_url" </dev/null >/dev/null 2>&1
                        pr_rc=$?
                        [ "$pr_variant" = plain ] && [ "$pr_scheme" = https ] && pr_https_rc=$pr_rc
                        ;;
                    wget)
                        # wget -S prints the response headers on stderr, indented
                        $in_ns wget -q -S -T 3 -t 1 --no-check-certificate -O "$pr_dir/body" \
                            "$pr_scheme://$pr_url_host:$pr_port/" </dev/null 2>&1 >/dev/null |
                            sed 's/^  //' > "$pr_dir/headers"
                        ;;
                    nc)
                        pr_limit=
                        [ "$timeout_style" = plain ] && pr_limit="timeout 4"
                        [ "$timeout_style" = old ] && pr_limit="timeout -t 4"
                        printf 'GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: webscan\r\n\r\n' |
                            $pr_limit $in_ns nc -w 3 "$pr_host" "$pr_port" > "$pr_dir/raw" 2>/dev/null
                        split_raw
                        ;;
                    bash)
                        run_with_timeout 3 $in_ns bash -c \
                            'exec 3<>/dev/tcp/$0/$1; printf "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3; dd bs=1000 count=20 <&3 2>/dev/null' \
                            "$pr_host" "$pr_port" > "$pr_dir/raw" 2>/dev/null
                        split_raw
                        ;;
                esac
                if grep -q '^HTTP/' "$pr_dir/headers"; then
                    http_status="$pr_scheme $(grep '^HTTP/' "$pr_dir/headers" | head -n 1 | tr -d '\r')"
                    http_server=$(grep -i '^server:' "$pr_dir/headers" | head -n 1 | cut -d' ' -f2- | tr -d '\r')
                    http_title=$(awk '{
                        line = tolower($0)
                        if (match(line, /<title[^>]*>/)) {
                            text = substr($0, RSTART + RLENGTH); sub(/<.*/, "", text)
                            print text; exit
                        }
                    }' "$pr_dir/body")
                    # a login page (HTML) or a Basic/Digest login prompt, as opposed
                    # to the bare JSON "401 unauthorized" that APIs send
                    http_login=
                    if grep -qiE '<html|<!doctype|<title' "$pr_dir/body" ||
                       grep -qiE '^www-authenticate: *(basic|digest)' "$pr_dir/headers"; then
                        http_login=yes
                    fi

                    # "400 ... you sent plain HTTP to an HTTPS port" (Go, nginx and
                    # Apache all say this): it is an HTTPS site, so ask again with
                    # TLS. The plain answer is kept in case that fails.
                    pr_code=$(awk '/^HTTP\// { print $2; exit }' "$pr_dir/headers")
                    if [ "$pr_scheme" = http ] && [ "$pr_code" = 400 ] &&
                       grep -qiE 'https|ssl|tls' "$pr_dir/body"; then
                        pr_plain=$http_status
                        pr_plain_server=$http_server
                        pr_plain_title=$http_title
                        http_status=
                        http_server=
                        http_title=
                        break
                    fi
                    return
                fi
                # curl exit 28 = timed out. On plain HTTP that can be a TLS-only
                # server waiting for a handshake, so https gets a try. If https
                # times out too, the port accepts connections but says nothing
                # (a database, a stuck service, a firewall): stop here instead of
                # spending more timeouts on the legacy retry and the TLS check.
                if [ "$pr_scheme" = https ] && [ "$fetcher" = curl ] && [ "$pr_rc" -eq 28 ]; then
                    pr_silent=yes
                    break 3
                fi
            done
        done
    done

    # No HTTP or HTTPS answer. If the port still speaks TLS, say so: it is most
    # likely an HTTPS site that only offers protocols/ciphers we can't use here.
    [ "$pr_silent" = yes ] && return
    if [ -z "$pr_tls" ]; then
        for pr_host in $pr_hosts; do
            speaks_tls "$pr_host" "$pr_port" && pr_tls=yes
        done
    fi
    if [ "$pr_tls" = yes ]; then
        http_status="(speaks TLS, but HTTPS could not be checked: legacy TLS or not a web service)"
    fi
}

probe() {
    probe_net "$@"
    if [ -z "$http_status" ] && [ -n "$pr_plain" ]; then
        http_status=$pr_plain
        http_server=$pr_plain_server
        http_title=$pr_plain_title
    fi
}


# --- 4. what a site runs on ----------------------------------------------------

# 12-character container id of a pid, if it runs in a container
container_id() {
    awk '{ for(i=1;i<=NF;i++) { n=split($i,a,/[\/:.-]/); for(j=1;j<=n;j++) if(length(a[j])==64 && a[j] !~ /[^0-9a-f]/) { print a[j]; exit } } }' /proc/"$1"/cgroup 2>/dev/null | head -n1 | cut -c1-12
}

# Prints the container (or Kubernetes pod) a pid runs in, if any.
container_info() {
    ci_id=$(awk '{ for(i=1;i<=NF;i++) { n=split($i,a,/[\/:.-]/); for(j=1;j<=n;j++) if(length(a[j])==64 && a[j] !~ /[^0-9a-f]/) { print a[j]; exit } } }' /proc/"$1"/cgroup 2>/dev/null | head -n1)
    [ -n "$ci_id" ] || return

    ci_info=
    if command -v docker >/dev/null 2>&1; then
        ci_info=$(run_with_timeout 3 docker inspect --format \
            '{{.Name}}  image={{.Config.Image}}  compose_dir={{index .Config.Labels "com.docker.compose.project.working_dir"}}  mounts={{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' \
            "$ci_id" 2>/dev/null)
    fi
    if [ -z "$ci_info" ] && grep -q kubepods /proc/"$1"/cgroup 2>/dev/null; then
        # a pod's hostname is the pod name
        ci_pod=$(tr '\0' '\n' < /proc/"$1"/environ 2>/dev/null | sed -n 's/^HOSTNAME=//p' | head -n1)
        [ -n "$ci_pod" ] || ci_pod=$(head -n1 /proc/"$1"/root/etc/hostname 2>/dev/null)
        ci_info="Kubernetes pod ${ci_pod:-?}"
    fi
    ci_short=$(printf '%s' "$ci_id" | cut -c1-12)
    field "Container:" "${ci_info:-unknown}  (id $ci_short)"
}

# Guesses what web application lives in a directory (or one of its two parents).
# Sets app_desc (what it is) and app_dir (where its files are).
detect_app() {
    da_dir=$1
    app_desc=
    app_dir=
    for da_d in "$da_dir" "$(dirname "$da_dir")" "$(dirname "$(dirname "$da_dir")")"; do
        app_dir=$da_d
        if   [ -f "$da_d/wp-config.php" ];              then app_desc="WordPress ($da_d)"; return
        elif [ -f "$da_d/artisan" ];                    then app_desc="Laravel ($da_d)"; return
        elif [ -f "$da_d/manage.py" ];                  then app_desc="Django ($da_d)"; return
        elif [ -f "$da_d/config/application.rb" ];      then app_desc="Rails ($da_d)"; return
        elif [ -f "$da_d/bin/magento" ];                then app_desc="Magento ($da_d)"; return
        elif [ -f "$da_d/configuration.php" ];          then app_desc="Joomla ($da_d)"; return
        elif [ -f "$da_d/sites/default/settings.php" ]; then app_desc="Drupal ($da_d)"; return
        elif [ -d "$da_d/WEB-INF" ];                    then app_desc="Java webapp ($da_d)"; return
        elif [ -f "$da_d/package.json" ]; then
            da_name=$(grep '"name"' "$da_d/package.json" | cut -d'"' -f4)
            app_desc="Node.js: $da_name ($da_d)"; return
        elif [ -f "$da_d/composer.json" ]; then
            da_name=$(grep '"name"' "$da_d/composer.json" | cut -d'"' -f4)
            app_desc="PHP: $da_name ($da_d)"; return
        elif [ -f "$da_d/program/include/iniset.php" ];  then app_desc="Roundcube webmail ($da_d)"; return
        elif [ -f "$da_d/occ" ];                        then app_desc="Nextcloud ($da_d)"; return
        elif [ -f "$da_d/LocalSettings.php" ];          then app_desc="MediaWiki ($da_d)"; return
        elif [ -f "$da_d/requirements.txt" ] || [ -f "$da_d/pyproject.toml" ] || [ -f "$da_d/app.py" ] || [ -f "$da_d/wsgi.py" ]; then
            app_desc="Python app ($da_d)"; return
        elif [ -f "$da_d/Gemfile" ];                    then app_desc="Ruby app ($da_d)"; return
        elif [ -f "$da_d/go.mod" ];                     then app_desc="Go app ($da_d)"; return
        elif [ -f "$da_d/pom.xml" ] || [ -f "$da_d/build.gradle" ]; then app_desc="Java app ($da_d)"; return
        fi
    done
    app_dir=$da_dir
    if [ -f "$da_dir/conf/conf.php" ]; then
        app_desc="Dolibarr ($da_dir)"
    elif [ -f "$da_dir/index.php" ]; then
        app_desc="plain PHP site"
    elif [ -f "$da_dir/index.html" ]; then
        app_desc="static HTML site"
    fi
}

# value of a PHP-style  define('KEY', 'value')  line
php_value() {
    awk -v key="$2" '
        index($0,key) {
            line=$0
            if (line ~ /define[ \t]*\(/) {
                sub(/^[^,]*,/, "", line)
            } else if (line ~ /=/) sub(/^[^=]*=/, "", line)
            else next
            sub(/^[ \t]+/, "", line)
            quote=substr(line,1,1)
            if (quote == "\042" || quote == "\047") {
                line=substr(line,2); pos=index(line,quote)
                if (pos) { print substr(line,1,pos-1); exit }
            }
        }' "$1" 2>/dev/null
}

# value of a KEY=value line in a .env file
env_value() {
    sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n1 | tr -d "\"'\r"
}

# Prints the database a web app is set up to use (WordPress and .env files), and
# which local process listens there. Never prints the password.
# $1 = folder with the app, $2 = namespace
db_info() {
    di_host=
    di_port=
    di_name=
    di_user=
    di_orig=
    if [ -f "$1/wp-config.php" ]; then
        di_host=$(php_value "$1/wp-config.php" DB_HOST)
        di_name=$(php_value "$1/wp-config.php" DB_NAME)
        di_user=$(php_value "$1/wp-config.php" DB_USER)
    elif [ -f "$1/conf/conf.php" ]; then
        di_host=$(php_value "$1/conf/conf.php" dolibarr_main_db_host)
        di_port=$(php_value "$1/conf/conf.php" dolibarr_main_db_port)
        di_name=$(php_value "$1/conf/conf.php" dolibarr_main_db_name)
        di_user=$(php_value "$1/conf/conf.php" dolibarr_main_db_user)
    elif [ -f "$1/.env" ]; then
        di_host=$(env_value "$1/.env" DB_HOST)
        di_port=$(env_value "$1/.env" DB_PORT)
        di_name=$(env_value "$1/.env" DB_DATABASE)
        di_user=$(env_value "$1/.env" DB_USERNAME)
        [ -z "$di_port" ] && [ "$(env_value "$1/.env" DB_CONNECTION)" = pgsql ] && di_port=5432
        [ -z "$di_host" ] && [ -n "$di_name" ] && di_host=127.0.0.1
    fi
    [ -n "$di_name" ] || return

    # WordPress writes "host:port" or "localhost:/path/to/socket"
    di_target=
    case $di_host in
        *:/*) di_target="unix:${di_host#*:}" ;;
        *:[0-9]*) di_port=${di_host##*:}; di_host=${di_host%:*} ;;
    esac
    if [ -z "$di_target" ]; then
        [ "$di_host" = localhost ] && di_orig=localhost
        if [ "$di_host" = localhost ] && [ -z "$di_port" ]; then
            di_socket=$(awk -v p="$pid" '
                /mysql|maria/ { print $1; exit }
            ' "$tmp/unix_owner")
            if [ -n "$di_socket" ]; then di_target="unix:$di_socket"; fi
        fi
        [ "$di_host" = localhost ] && di_host=127.0.0.1
        [ -n "$di_target" ] || di_target="$di_host:${di_port:-3306}"
    fi
    di_who=$(target_owner "$di_target" "$2")
    case $di_who in
        "nothing listening"*)
            # PHP connects to "localhost" through the database's socket file, not
            # through port 3306, so a database without a TCP port is not down
            if [ "$di_orig" = localhost ]; then
                di_sock=$(awk '$1 ~ /mysql|maria/ { print $1 " " $2; exit }' "$tmp/unix_owner")
                if [ -n "$di_sock" ]; then
                    di_who="$(proc_name "${di_sock#* }") (pid ${di_sock#* }), through its socket ${di_sock% *}"
                fi
            fi ;;
    esac
    case $di_who in
        "nothing listening"*) di_who="$di_who (database down?)" ;;
    esac
    sub_field "Database:" "$di_name on $di_target (user $di_user)${di_who:+   -> $di_who}"
}

# Prints a web root with the web app found in it. $1 = path as the process sees
# it. Uses $pid and $ns.
show_root() {
    sr_real=/proc/$pid/root$1
    sub_field "Web root:" "$1"
    if [ "$ns" != "$host_ns" ] || [ -n "$(container_id "$pid")" ]; then
        sub_field "On host:" "$sr_real"
    fi
    if [ ! -d "$sr_real" ]; then
        sub_field "Web app:" "(folder not found or not readable)"
        return
    fi
    detect_app "$sr_real"
    sub_field "Code/root:" "${app_dir#/proc/$pid/root}"
    sub_field "Web app:" "$(printf '%s' "${app_desc:-not recognised}" | sed "s|/proc/$pid/root||g")"
    for sr_file in package.json package-lock.json yarn.lock composer.json composer.lock requirements.txt pyproject.toml Gemfile Gemfile.lock go.mod pom.xml build.gradle web.config; do
        [ -f "$app_dir/$sr_file" ] && sub_field "Dependency:" "${app_dir#/proc/$pid/root}/$sr_file"
    done
    for sr_folder in "$sr_real" "$sr_real"/*; do
        [ -d "$sr_folder" ] || continue
        case $sr_folder in */node_modules|*/vendor|*/.git|*/venv|*/.venv) continue ;; esac
        for sr_candidate in "$sr_folder"/*; do
            [ -f "$sr_candidate" ] && printf '%s\n' "$sr_candidate"
        done
    done | awk '
        /\/(node_modules|vendor|\.git|venv|\.venv)\// { next }
        /\.(php|py|js|ts|rb|html|htm|jsp|aspx|sh)$/ { print; if (++n == 8) exit }
    ' | while read -r sr_code; do sub_field "Code file:" "${sr_code#/proc/$pid/root}"; done
    for sr_source in "$sr_real"/*.py "$sr_real"/*.js "$sr_real"/*.php; do
        [ -f "$sr_source" ] || continue
        awk '/(DB_HOST|DB_NAME|DB_DATABASE|DB_PORT|DB_USER)[ \t]*=/ {
            line=$0; sub(/^[ \t]+/, "", line)
            if (line ~ /PASS|SECRET|TOKEN/) next
            print line
        }' "$sr_source" | head -n 8 | while read -r sr_hint; do sub_field "DB hint:" "$sr_hint [$sr_source; verify configuration]"; done
        awk '{
            text=$0
            while (match(text, /https?:\/\/[^ \t\042\047<>]+/)) {
                url=substr(text,RSTART,RLENGTH); text=substr(text,RSTART+RLENGTH)
                sub(/[?#].*/, "", url)
                if (url !~ /@/) print url
            }
        }' "$sr_source" | sort -u | head -n 8 | while read -r sr_url; do
            sub_field "URL hint:" "$sr_url [$sr_source; verify configuration]"
        done
    done
    db_info "$app_dir" "$ns"
}

# nginx: one SITE line per server block, then its ROOT and PROXY lines.
#   SITE|<file>|,<port>,<port>|<server names>
#   ROOT|<path>
#   PROXY|<directive>|<target>
# The config text comes in with "#FILE <name>" lines between the files.
parse_nginx() {
    awk '
        function trim(s) {
            gsub(/^[ \t\r\n]+/, "", s)
            gsub(/[ \t\r\n]+$/, "", s)
            gsub(/[ \t\r\n]+/, " ", s)
            return s
        }
        function statement(s,   n, w, k, p, j) {
            s = trim(s)
            if (s == "") return
            n = split(s, w, " ")
            k = w[1]
            if (kind[depth] == "upstream") {
                if (k == "server") ups[up_name] = ups[up_name] " " w[2]
                return
            }
            if (!in_server) return
            if (k == "listen") {
                p = w[2]
                sub(/^.*:/, "", p)                # 127.0.0.1:8080 and [::]:80 -> port
                if (p ~ /^[0-9]+$/) ports = ports "," p
            } else if (k == "server_name") {
                for (j = 2; j <= n; j++) names = names " " w[j]
            } else if (k == "root") {
                nroot++; root_of[nroot] = w[2]
            } else if (k == "set" && n >= 3) {
                # set $backend "app:8000";   used later in proxy_pass http://$backend
                nset++; set_name[nset] = w[2]; v = w[3]; gsub(/["\047]/, "", v); set_value[nset] = v
            } else if (k ~ /^(proxy_pass|fastcgi_pass|uwsgi_pass|scgi_pass|grpc_pass)$/) {
                nprox++; prox_dir[nprox] = k; prox_target[nprox] = w[2]
            }
        }
        function open_block(h,   w, n) {
            n = split(trim(h), w, " ")
            depth++
            kind[depth] = "other"
            if (w[1] == "upstream") {
                kind[depth] = "upstream"
                up_name = w[2]
            } else if (w[1] == "server" && n == 1 && !in_server) {
                kind[depth] = "server"
                in_server = 1
                ports = ""; names = ""; nroot = 0; nprox = 0; nset = 0
            }
        }
        function close_block(   j, v, t, i, guard) {
            if (kind[depth] == "server") {
                blocks++
                b_file[blocks] = file
                b_ports[blocks] = (ports == "" ? ",80" : ports)
                b_names[blocks] = trim(names)
                b_nroot[blocks] = nroot
                for (j = 1; j <= nroot; j++) b_root[blocks, j] = root_of[j]
                b_nprox[blocks] = nprox
                for (j = 1; j <= nprox; j++) {
                    t = prox_target[j]
                    for (v = 1; v <= nset; v++) {      # fill in variables set in this server
                        guard = 0
                        while ((i = index(t, set_name[v])) > 0 && guard++ < 5)
                            t = substr(t, 1, i - 1) set_value[v] substr(t, i + length(set_name[v]))
                    }
                    b_dir[blocks, j] = prox_dir[j]; b_target[blocks, j] = t
                }
                in_server = 0
            }
            if (depth > 0) depth--
        }
        /^#FILE / { file = substr($0, 7); next }
        {
            sub(/#.*/, "")                        # comments
            line = $0 " "
            for (c = 1; c <= length(line); c++) {
                ch = substr(line, c, 1)
                if (ch == ";")      { statement(buf); buf = "" }
                else if (ch == "{") { open_block(buf); buf = "" }
                else if (ch == "}") { close_block(); buf = "" }
                else                  buf = buf ch
            }
        }
        END {
            for (b = 1; b <= blocks; b++) {
                print "SITE|" b_file[b] "|" b_ports[b] "|" b_names[b]
                for (j = 1; j <= b_nroot[b]; j++) print "ROOT|" b_root[b, j]
                for (j = 1; j <= b_nprox[b]; j++) {
                    t = b_target[b, j]
                    name = t
                    sub(/^[a-z]+:\/\//, "", name)
                    sub(/[\/:;].*$/, "", name)
                    # "proxy_pass http://backend" where backend is an upstream block
                    if (name in ups) {
                        n = split(trim(ups[name]), us, " ")
                        for (k = 1; k <= n; k++) print "PROXY|" b_dir[b, j] " [" name "]|" us[k]
                    } else {
                        print "PROXY|" b_dir[b, j] "|" t
                    }
                }
            }
        }'
}

# Apache: the same SITE/ROOT/PROXY lines, one SITE per <VirtualHost>. Settings
# outside any <VirtualHost> become a "default" SITE.
parse_apache() {
    awk '
        function unquote(s) { gsub(/"/, "", s); return s }
        function start(f, p, n) {
            nroot = 0; nprox = 0; ports = p; names = n; sfile = f
        }
        function finish(   j, name) {
            if (nroot == 0 && nprox == 0 && !is_vhost) return
            sub(/^ +/, "", names)
            print "SITE|" sfile "|" ports "|" names
            for (j = 1; j <= nroot; j++) print "ROOT|" root_of[j]
            for (j = 1; j <= nprox; j++) print "PROXY|" prox_dir[j] "|" prox_target[j]
        }
        function proxy(d, t) { nprox++; prox_dir[nprox] = d; prox_target[nprox] = unquote(t) }
        /^#FILE / { file = substr($0, 7); next }
        {
            sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "")
            if ($0 == "" || $0 ~ /^#/) next
            d = tolower($1)
        }
        d == "<virtualhost" {
            vports = ""
            for (j = 2; j <= NF; j++) {
                a = $j; sub(/>.*$/, "", a)
                if (a == "") continue
                if (a ~ /:/) { sub(/^.*:/, "", a); vports = vports "," a } else vports = vports ",*"
            }
            # settings seen so far belong to the main server: print them first
            is_vhost = 0
            if (main_started) { sfile = main_file; ports = "default"; names = "(default server)"; finish() }
            main_started = 0
            is_vhost = 1
            start(file, vports, "")
            next
        }
        d == "</virtualhost>" { finish(); is_vhost = 0; nroot = 0; nprox = 0; ports = ""; next }
        d == "servername" || d == "serveralias" { if (is_vhost) names = names " " $2; next }
        d == "documentroot" {
            if (!is_vhost && !main_started) { main_started = 1; main_file = file; nroot = 0; nprox = 0 }
            nroot++; root_of[nroot] = unquote($2); next
        }
        d == "proxypass" {
            if ($2 == "!") next
            if (!is_vhost && !main_started) { main_started = 1; main_file = file; nroot = 0; nprox = 0 }
            proxy("ProxyPass", ($2 ~ /^"?\// ? $3 : $2)); next
        }
        d == "proxypassmatch" {
            if (!is_vhost && !main_started) { main_started = 1; main_file = file; nroot = 0; nprox = 0 }
            proxy("ProxyPassMatch", $3); next
        }
        d == "sethandler" && $2 ~ /proxy:/ {
            t = unquote($2); sub(/^proxy:/, "", t)
            if (!is_vhost && !main_started) { main_started = 1; main_file = file; nroot = 0; nprox = 0 }
            proxy("SetHandler proxy", t); next
        }
        END {
            if (main_started && !is_vhost) { sfile = main_file; ports = "default"; names = "(default server)"; finish() }
        }'
}

# For nginx/apache: finds the vhosts that listen on this port and prints each
# with its web root(s), web app and backends. Returns 1 if it printed nothing
# (not a web server we know, no config found, or no vhost for this port).
# $1 = pid, $2 = process name. Uses $id, $port, $ns.
show_sites() {
    ss_pid=$1
    ss_base=/proc/$ss_pid/root
    case $2 in
        nginx|openresty)
            ss_dirs="/etc/nginx /usr/local/nginx/conf /usr/local/etc/nginx /opt/nginx/conf"
            ss_parser=parse_nginx ;;
        apache2|httpd|apache)
            ss_dirs="/etc/apache2 /etc/httpd /usr/local/apache2/conf /opt/apache2/conf"
            ss_parser=parse_apache ;;
        *)
            return 1 ;;
    esac

    # a config given on the command line (-c for nginx, -f for Apache)
    ss_arg=$(tr '\0' ' ' < /proc/"$ss_pid"/cmdline 2>/dev/null |
        awk '{ for (i = 1; i < NF; i++) if ($i == "-c" || $i == "-f") { print $(i + 1); exit } }')
    case $ss_arg in
        /*) case " $ss_dirs " in
                *" $(dirname "$ss_arg") "*) ;;            # already in the list
                *) ss_dirs="$ss_dirs $(dirname "$ss_arg")" ;;
            esac ;;
    esac

    ss_existing=
    for ss_d in $ss_dirs; do
        [ -d "$ss_base$ss_d" ] && ss_existing="$ss_existing $ss_base$ss_d"
    done
    [ -n "$ss_existing" ] || return 1

    find $ss_existing -follow -type f ! -path '*-available/*' 2>/dev/null | sort -u |
        while read -r ss_f; do
            echo "#FILE $ss_f"
            cat "$ss_f" 2>/dev/null
        done | $ss_parser > "$tmp/blocks.$id"

    # vhosts for this port ("*" = any port); if none, the default server
    awk -F'|' -v p="$port" '
        $1 == "SITE" { keep = (index($3 ",", "," p ",") > 0 || index($3, "*") > 0) }
        keep' "$tmp/blocks.$id" > "$tmp/mine.$id"
    if [ ! -s "$tmp/mine.$id" ]; then
        awk -F'|' '$1 == "SITE" { keep = ($3 == "default") } keep' "$tmp/blocks.$id" > "$tmp/mine.$id"
    fi
    [ -s "$tmp/mine.$id" ] || return 1
    # (a config often repeats the same root or proxy line in several locations)
    awk '$0 ~ /^SITE\|/ { split("", seen) } !seen[$0]++' "$tmp/mine.$id" > "$tmp/mine2.$id"
    mv "$tmp/mine2.$id" "$tmp/mine.$id"

    while IFS='|' read -r ss_kind ss_a ss_b ss_c; do
        case $ss_kind in
            SITE)
                field "Site:" "${ss_c:-(no server name)}   [${ss_a#$ss_base}]" ;;
            ROOT)
                show_root "$ss_a" ;;
            PROXY)
                ss_who=$(target_owner "$ss_b" "$ns")
                sub_field "Backend:" "$ss_a $ss_b${ss_who:+   -> $ss_who}" ;;
        esac
    done < "$tmp/mine.$id"
    return 0
}


# Traefik (the k3s ingress) sends each request to a site by its hostname. Says
# which hostnames Kubernetes has set up, if kubectl could tell us.
traefik_sites() {
    ts_hosts=$(awk '$3 != "<none>" && $3 != "" { n = split($3, h, ","); for (i = 1; i <= n; i++) printf "%s (%s/%s)  ", h[i], $1, $2 }' "$tmp/k8s_ingress")
    if [ -n "$ts_hosts" ]; then
        field "Sites:" "Traefik picks the site by hostname: $ts_hosts"
    elif [ -n "$kube" ]; then
        field "Note:" "Traefik picks the site by hostname, so a plain request gets a 404. kubectl found no hostnames (a k3s worker node can't ask the cluster: run 'k3s kubectl get ingress -A' on the server node)"
    else
        field "Note:" "Traefik picks the site by hostname, so a plain request gets a 404 (kubectl is not here to list the hostnames)"
    fi
}

# --- 5. describe one port ------------------------------------------------------

# Writes everything to say about one port to $tmp/out.<id>. The first line says
# what it is:
#   site      a website bound for remote access; the full details follow
#   internal  a web server only this machine or other containers can reach; the
#             second line is "<pid>|<port>|<full or short>|<one-line summary>",
#             then the full details
#   other     not a website: nothing to print
#   skip      reported elsewhere: nothing to print
# Runs in the background, one per port, so a slow port only delays itself.
# $1 = number, $2 = namespace, $3 = port, $4 = bound address, $5 = pid (0 = unknown)
describe_port() {
    id=$1
    ns=$2
    port=$3
    addr=$4
    pid=$5

    rep_pid=$(awk -v n="$ns" '$1 == n { print $2; exit }' "$tmp/namespaces")
    comm=
    exe=
    if [ "$pid" -ne 0 ]; then
        comm=$(proc_name "$pid")
        exe=$(readlink /proc/"$pid"/exe 2>/dev/null)
    fi

    # A docker-proxy that forwards into a container we can see is not a separate
    # service: the container's own port shows it as "Published".
    if [ "$comm" = docker-proxy ]; then
        dp_port=$(awk -v pid="$pid" '$3 == pid { print $1; exit }' "$tmp/forwards")
        if [ -n "$dp_port" ] &&
           awk -F'|' -v p="$dp_port" -v hn="$host_ns" '$2 == p && $1 != hn && $1 != "nat" { f = 1 } END { exit !f }' "$tmp/sites"; then
            echo skip > "$tmp/out.$id.tmp"
            mv "$tmp/out.$id.tmp" "$tmp/out.$id"
            return
        fi
    fi

    probe "$id" "$rep_pid" "$ns" "$port" "$addr"
    code=$(printf '%s\n' "$http_status" | awk '$2 ~ /^HTTP\// { print $3 }')

    # Can other machines connect to it? On the host: unless it is bound to
    # localhost. In a container: only if a host port is published to it, by
    # Docker's proxy or by a firewall rule (Kubernetes NodePort, hostPort, ...).
    pubs=
    cname=
    if [ "$ns" = "$host_ns" ]; then
        case $addr in
            127.*|::1) reach=no ;;
            *)         reach=yes ;;
        esac
    else
        cname=$(ns_container_name "$ns")
        pubs=$(published_ports "$ns" "$port")
        if [ -n "$pubs" ]; then reach=yes; else reach=no; fi
    fi

    # Is it a website? Judged by what it does, not by what it is called: it answers
    # with a page (or asks for a login), or it is a web server / app runtime, or it
    # looks like malware. Everything else is left out.
    class=other
    tls_only=no
    case $http_status in
        "(speaks TLS"*) tls_only=yes ;;
    esac
    warning=
    case $exe in
        *"(deleted)"*)                         warning="binary was deleted from disk but is still running" ;;
        /tmp/*|/var/tmp/*|/dev/shm/*|/memfd:*) warning="binary runs from a temp or memory location" ;;
    esac
    if [ "$pid" -eq 0 ]; then
        [ -n "$code" ] && class=site
    else
        case $code in
            [1-5][0-9][0-9]) class=site ;;
            401|403)     [ -n "$http_login" ] && class=site ;;
        esac
        # (a web server or proxy can answer 404 or refuse us only because we
        # asked for the wrong hostname, so it counts anyway)
        if [ -n "$code" ] || [ "$tls_only" = yes ]; then
            case $comm in
                nginx|openresty|tengine|apache*|httpd|caddy|lighttpd|traefik|haproxy|envoy|varnish*|squid|php*|node|nodejs|deno|bun|gunicorn*|uwsgi*|uvicorn|hypercorn|python*|ruby*|puma|unicorn*|passenger*|java|tomcat*|jetty|dotnet|ttyd)
                    class=site ;;
            esac
        fi
        # a port that speaks TLS but refused us: likely a site that wants a
        # hostname or a client certificate
        if [ "$tls_only" = yes ]; then
            case $port in
                443|8443|4443|9443) class=site ;;
            esac
        fi
        [ -n "$warning" ] && class=site
    fi

    # not a website: nothing to report
    if [ "$comm" = traefik ]; then
        tcmd=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)
        tep=$(printf '%s' "$tcmd" | tr ' ' '\n' |
            sed -n "s/^--entryPoints\.\([^.]*\)\.address=:$port\(\/tcp\)\{0,1\}\$/\1/p" | head -n1)
        case $tep in
            traefik|metrics) class=other ;;     # its own dashboard/API and Prometheus port
        esac
    fi
    case $comm in
        portainer|dockerd|kube-apiserver|kubelet|k3s*|containerd|coredns|metrics-server|tor) class=other ;;
    esac
    # Inspect existing script arguments regardless of the executable's name.
    tr '\0' '\n' < /proc/"$pid"/cmdline 2>/dev/null > "$tmp/args.$id"
    while read -r source_arg; do
        case $source_arg in
            *.py|*.php|*.js|*.ts|*.rb|*.sh|*.jar|*.war|*.dll)
                case $source_arg in
                    /*) source_path=/proc/$pid/root$source_arg ;;
                    *) source_path=/proc/$pid/root$cwd/$source_arg ;;
                esac
                [ -f "$source_path" ] && class=site ;;
        esac
    done < "$tmp/args.$id"
    if [ "$class" = other ]; then
        echo other > "$tmp/out.$id.tmp"
        mv "$tmp/out.$id.tmp" "$tmp/out.$id"
        return
    fi

    # The port a visitor uses: the host port for something in a container.
    label=$port
    if [ -n "$pubs" ]; then
        label=$(printf '%s\n' "$pubs" | sed -n '1s/ .*//p')
    fi
    entry_label=$label
    if [ "$reach" = yes ]; then
        [ "$pid" -ne 0 ] && echo "$pid $label" >> "$tmp/entry_pids"
        kind=site
        if [ "$ns" = "$host_ns" ]; then
            case $addr in
                0.0.0.0|::) header="port $port (bound for remote access; firewall not checked)" ;;
                *)          header="port $port (bound for remote access; firewall not checked, bound to $addr only)" ;;
            esac
        elif [ "$label" = "$port" ]; then
            header="port $label (bound for remote access; firewall not checked; runs in a container)"
        else
            header="port $label (bound for remote access; firewall not checked; runs in a container, as port $port there)"
        fi
    else
        kind=internal
        entry_label=$port
        if [ "$ns" = "$host_ns" ]; then
            header="port $port (internal: only programs on this machine can connect; @USED@)"
        else
            header="port $port (internal: private namespace; routing may expose it; @USED@)"
        fi
    fi

    {
        echo "$kind"
        if [ "$kind" = internal ]; then
            flag=full
            { [ "$pid" -eq 0 ] || [ -n "$warning" ]; } && flag=full
            summary="port $port: ${comm:-unknown process}${pid:+ (pid $pid)}${cname:+, container $cname}; ${http_status}${http_title:+; $http_title}${warning:+; WARNING: $warning}"
            echo "$pid|$port|$flag|$summary"
        fi
        echo
        echo "== $header =="
        if [ -n "$http_status" ]; then
            field "Bindings:" "$(awk -F'|' -v n="$ns" -v p="$port" -v owner="$pid" '$1==n && $2==p && $4==owner { printf "%s:%s ", $3,$2 }' "$tmp/sites")"
        field "HTTP:" "$http_status${http_server:+  Server: $http_server}${http_title:+  Title: $http_title}"
        fi

        if [ "$pid" -eq 0 ]; then
            if [ "$is_root" = yes ]; then
                field "Process:" "UNKNOWN - no visible process owns this socket (hidden process?)"
            else
                field "Process:" "unknown (owned by another user, run as root to see it)"
            fi
        else
            cwd=$(readlink /proc/"$pid"/cwd 2>/dev/null)
            cmdline=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null)
            owner=$(ls -ld /proc/"$pid" 2>/dev/null | awk '{ print $3 }')
            field "Process:" "$comm (pid $pid, user $owner)"
            field "Binary:" "${exe:-unknown}"
            if [ "${#cmdline}" -gt 200 ]; then
                field "Command:" "$(printf '%s' "$cmdline" | cut -c1-200)..."
            else
                field "Command:" "$cmdline"
            fi
            container_info "$pid"
            if [ -n "$pubs" ]; then
                printf '%s\n' "$pubs" | while read -r ph how; do
                    field "Published:" "host port $ph ($how) -> this container's port $port"
                done
            fi
            if [ "$comm" = traefik ]; then
                ep=$(printf '%s' "$cmdline" | tr ' ' '\n' |
                    sed -n "s/^--entryPoints\.\([^.]*\)\.address=:$port\(\/tcp\)\{0,1\}\$/\1/p" | head -n1)
                if [ -n "$ep" ]; then
                    field "Entrypoint:" "$ep"
                    traefik_sites
                fi
            fi

            # vhosts from the web server config, else the process's own folder
            if ! show_sites "$pid" "$comm"; then
                case $cwd in
                    ''|/) ;;
                    *)    show_root "$cwd" ;;
                esac
            fi
        fi
        [ -n "$warning" ] && field "WARNING:" "$warning"
    } > "$tmp/out.$id.tmp"
    mv "$tmp/out.$id.tmp" "$tmp/out.$id"
}


# The same for a port that a firewall rule forwards. A rule rewrites where the
# traffic goes, so the kernel passes it on without any program holding the port
# here. Only reported if something answers on it.
# $1 = number, $2 = port, $3 = this machine's address
describe_nat() {
    id=$1
    port=$2
    addr=$3
    ns=$host_ns
    probe "$id" "$$" "$host_ns" "$port" "$addr"
    case $http_status in
        ''|"(not probed"*)
            echo skip > "$tmp/out.$id.tmp"
            mv "$tmp/out.$id.tmp" "$tmp/out.$id"
            return ;;
    esac
    nd=$(awk -v p="$port" '$1 == p { print $2; exit }' "$tmp/nat_dest")
    svc=$(awk -v p="$port" '$1 == p { print $3; exit }' "$tmp/nat_dest")
    listener=$(who_listens "$port" "$host_ns")
    {
        echo site
        echo
        if [ -z "$nd" ] || [ "$nd" = - ]; then
            echo "== port $port (answers on this machine's address, but no program here listens on it and I can't read the rule that forwards it) =="
        elif [ -n "$listener" ]; then
            echo "== port $port (bound for remote access; firewall not checked; a firewall rule sends it elsewhere, so they never reach the program listening here) =="
        else
            echo "== port $port (bound for remote access; firewall not checked; a firewall rule sends it elsewhere, no program on this machine listens on it) =="
        fi
        field "HTTP:" "$http_status${http_server:+  Server: $http_server}${http_title:+  Title: $http_title}"
        [ -n "$listener" ] && field "Listening:" "$listener, but the firewall rule takes the traffic first"
        if [ -n "$svc" ] && [ "$svc" != - ]; then
            field "Service:" "Kubernetes service $svc"
        fi
        if [ -n "$nd" ] && [ "$nd" != - ]; then
            printf '%s\n' "$nd" | tr ',' '\n' | while read -r d; do
                nd_ip=${d%:*}
                nd_ns=$(awk -v ip="$nd_ip" '$2 == ip { print $1; exit }' "$tmp/ns_ips")
                if [ -n "$nd_ns" ] && [ "$nd_ns" != "$host_ns" ]; then
                    nd_pid=$(awk -v n="$nd_ns" '$1 == n { print $2; exit }' "$tmp/namespaces")
                    nd_cn=$(ns_container_name "$nd_ns")
                    nd_who=$(who_listens "${d##*:}" "$nd_ns")
                    nd_text="container ${nd_cn:-$(container_id "$nd_pid")}: ${nd_who:-no program listens there, that pod forwards it again, usually the Kubernetes load balancer}"
                elif [ -n "$nd_ns" ]; then
                    nd_text="this machine: $(who_listens "${d##*:}" "$nd_ns")"
                else
                    nd_text=$(awk -v ip="$nd_ip" '$3 == ip { print "pod " $1 "/" $2 " on node " $4; exit }' "$tmp/k8s_pods")
                    [ -n "$nd_text" ] || nd_text="not an address on this machine, probably a pod on another node"
                fi
                field "Sent to:" "$d   ($nd_text)"
            done
            case $nd in
                *,*) field "Note:" "more than one target: the rules share the traffic, or more than one rule matches this port" ;;
            esac
        fi
        case $svc in
            *traefik*) traefik_sites ;;
        esac
    } > "$tmp/out.$id.tmp"
    mv "$tmp/out.$id.tmp" "$tmp/out.$id"
}


# --- 6. run it and report ------------------------------------------------------

# Prints the internal web servers (the ones other machines can't connect to).
# Ones that a site above sends traffic to are shown in full, as part of that
# site; the rest get one line each.
print_internal() {
    : > "$tmp/int_full"
    : > "$tmp/int_short"
    while read -r pi_id; do
        pi_meta=$(sed -n 2p "$tmp/out.$pi_id")
        pi_pid=${pi_meta%%|*};  pi_rest=${pi_meta#*|}
        pi_port=${pi_rest%%|*}; pi_rest=${pi_rest#*|}
        pi_flag=${pi_rest%%|*}; pi_sum=${pi_rest#*|}

        pi_by=
        pi_same=
        if [ "$pi_pid" -ne 0 ]; then
            pi_by=$(awk -v p="$pi_pid" -v q="$pi_port" '$1 == p && $2 == q { print $3 }' "$tmp/used" |
                sort -un | tr '\n' ' ' | sed 's/ $//; s/ /, /g')
            pi_same=$(awk -v p="$pi_pid" '$1 == p { print $2; exit }' "$tmp/entry_pids")
        fi
        if [ -n "$pi_by" ]; then
            pi_text="used by the site on port $pi_by"
        elif [ -n "$pi_same" ]; then
            pi_text="part of the same program as port $pi_same"
        else
            pi_text="no site above sends traffic to it"
        fi

        if [ -n "$pi_by" ] || [ "$pi_flag" = full ]; then
            sed '1,2d' "$tmp/out.$pi_id" | sed "s|@USED@|$pi_text|" >> "$tmp/int_full"
        else
            echo "  $pi_sum   [$pi_text]" >> "$tmp/int_short"
        fi
    done < "$tmp/internal_ids"

    if [ -s "$tmp/int_full" ]; then
        echo
        echo "-- Internal servers behind the sites above (other machines can't connect to these directly) --"
        cat "$tmp/int_full"
    fi
    if [ -s "$tmp/int_short" ]; then
        echo
        echo "-- Other internal web servers (other machines can't connect to these directly) --"
        cat "$tmp/int_short"
    fi
}

probe_start=$(date +%s 2>/dev/null)
case $probe_start in ''|*[!0-9]*) probe_start=$start ;; esac
echo "inventory_services on $(hostname 2>/dev/null || cat /proc/sys/kernel/hostname), $(date '+%Y-%m-%d %H:%M:%S')"

# Describe every port at the same time, in the background (at most 64 at once).
# Their output is discarded: they write to files, and must not keep the SSH
# session open after the script ends.
(
    i=0
    running=0
    while IFS='|' read -r ns port addr pid <&3; do
        [ -n "$port" ] || continue
        i=$((i + 1))
        if [ "$ns" = nat ]; then
            ( describe_nat "$i" "$port" "$addr" ) >/dev/null 2>&1 &
        else
            ( describe_port "$i" "$ns" "$port" "$addr" "$pid" ) >/dev/null 2>&1 &
        fi
        running=$((running + 1))
        if [ "$running" -ge 64 ]; then
            wait
            running=0
        fi
    done 3< "$tmp/sites"
    wait
) >/dev/null 2>&1 &

# Print each reachable site as soon as its description is ready, in port order.
# Internal ones are collected and printed after them.
: > "$tmp/unchecked"
: > "$tmp/internal_ids"
shown=0
: > "$tmp/reported"
: > "$tmp/json_reports"
timed_out=no
i=0
while IFS='|' read -r ns port addr pid <&3; do
    [ -n "$port" ] || continue
    i=$((i + 1))
    while [ ! -f "$tmp/out.$i" ] && [ "$timed_out" = no ]; do
        if out_of_time; then
            timed_out=yes
        else
            sleep 1
        fi
    done
    if [ ! -f "$tmp/out.$i" ]; then
        echo "  port $port ($(bind_address "$addr"))" >> "$tmp/unchecked"
        continue
    fi
    report_kind=$(sed -n 1p "$tmp/out.$i")
    case $report_kind in
        site|internal)
            report_key="$ns|$port|$pid"
            grep -Fxq "$report_key" "$tmp/reported" && continue
            printf '%s\n' "$report_key" >> "$tmp/reported"
            cat "$tmp/out.$i" >> "$tmp/json_reports" ;;
    esac
    case $report_kind in
        site)
            shown=$((shown + 1))
            sed 1d "$tmp/out.$i" ;;
        internal)
            echo "$i" >> "$tmp/internal_ids" ;;
    esac
done 3< "$tmp/sites"

print_internal

echo
n_internal=$(wc -l < "$tmp/internal_ids" | tr -d ' ')
if [ -s "$tmp/unchecked" ]; then
    echo
    echo "WARNING: ran out of time ($budget seconds) before these ports were checked:"
    cat "$tmp/unchecked"
fi

echo "Summary: $shown entry point(s), $n_internal internal code/web service(s), $(wc -l < "$tmp/unchecked" | tr -d ' ') unchecked listener(s)."

# ---------------------------------------------------------------------------
# Suggested nmap command — run this from your attack box for deeper scanning.
# ---------------------------------------------------------------------------
_nmap_ports=$(awk -F'|' '{ print $2 }' "$tmp/sites" 2>/dev/null | sort -un | tr '\n' ',' | sed 's/,$//')
if [ -n "$_nmap_ports" ] && [ -n "$local_ip" ]; then
    echo ""
    echo "# Suggested nmap (run from your attack box):"
    echo "nmap -sV --script vuln -T5 -p $_nmap_ports $local_ip"
fi

# ---------------------------------------------------------------------------
# Cache JSON to a well-known path so other scripts on this machine can skip
# re-running inventory. Other scripts check /tmp/ccdc_inv.json first.
# ---------------------------------------------------------------------------
_inv_cache="/tmp/ccdc_inv.json"

# A single JSON line is the last stdout record. Read only completed, selected
# reports, including internal services. No Python/jq dependency is required.
hostname 2>/dev/null > "$tmp/json_machine"
[ -s "$tmp/json_machine" ] || cat /proc/sys/kernel/hostname > "$tmp/json_machine"
awk -v unchecked="$(wc -l < "$tmp/unchecked" | tr -d ' ')" '
    function quote(s,   i,c,out,j) {
        out = "\""
        for (i=1; i<=length(s); i++) {
            c=substr(s,i,1)
            if (c == "\"") out=out "\\\""
            else if (c == "\\") out=out "\\\\"
            else if (c == "\t") out=out "\\t"
            else if (c == "\r") out=out "\\r"
            else if (c == "\n") out=out "\\n"
            else if (c ~ /[[:cntrl:]]/) {
                for (j=1; j<32; j++) if (c == sprintf("%c",j)) break
                out=out sprintf("\\u%04x",j<32 ? j : 127)
            }
            else out=out c
        }
        return out "\""
    }
    function roots(service,   j,out) {
        out="["
        for (j=1; j<=nr[service]; j++) out=out (j>1 ? "," : "") quote(root[service,j])
        return out "]"
    }
    FILENAME == ARGV[1] { machine=$0; next }
    /^== / { n++; name[n]=$0; sub(/^== /,"",name[n]); sub(/ ==$/,"",name[n]); next }
    n && /^ +[^:]+:/ {
        line=$0; sub(/^ +/,"",line); key=line; sub(/:.*/,"",key)
        sub(/^[^:]+: */,"",line)
        if (key == "Code/root") {
            if (!seen[n,line]++) root[n,++nr[n]]=line
            if (!allseen[line]++) root[0,++nr[0]]=line
        }
        if (key ~ /^(Process|Container|Service|Bindings|HTTP|Site|Web root|On host|Web app|Backend|Database|DB hint|URL hint|Sent to|Listening|Published)$/) {
            if (!fieldseen[n,key]++) fields[n,++nf[n]]=key
            values[n,key,++nv[n,key]]=line
        }
    }
    END {
        printf "{\"schema_version\":1,\"machine\":%s,\"codebase_root_dirs\":%s,\"incomplete\":%s,\"services\":[", quote(machine),roots(0),(unchecked+0 ? "true" : "false")
        for (i=1; i<=n; i++) {
            printf "%s{\"name\":%s,\"codebase_root_dirs\":%s,\"details\":{",(i>1 ? "," : ""),quote(name[i]),roots(i)
            for (j=1; j<=nf[i]; j++) {
                key=fields[i,j]; printf "%s%s:[",(j>1 ? "," : ""),quote(key)
                for (k=1; k<=nv[i,key]; k++) printf "%s%s",(k>1 ? "," : ""),quote(values[i,key,k])
                printf "]"
            }
            printf "}}"
        }
        print "]}"
    }' "$tmp/json_machine" "$tmp/json_reports" | tee "$_inv_cache"
