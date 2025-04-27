#!/usr/bin/env bash
#
# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
#
function exists() { command -v "$1" >/dev/null 2>&1 ; }

if [[ -z "$1" ]]; then
  echo "Error: please specify a configuration file, e.g. $0 /etc/ipset-blacklist/ipset-blacklist.conf"
  exit 1
fi

# shellcheck source=ipset-blacklist.conf
if ! source "$1"; then
  echo "Error: can't load configuration file $1"
  exit 1
fi

if ! exists curl && exists egrep && exists grep && exists ipset && exists iptables && exists ip6tables && exists sed && exists sort && exists wc ; then
  echo >&2 "Error: searching PATH fails to find executables among: curl egrep grep ipset iptables ip6tables sed sort wc"
  exit 1
fi

DO_OPTIMIZE_CIDR=no
if exists iprange && [[ ${OPTIMIZE_CIDR:-yes} != no ]]; then
  DO_OPTIMIZE_CIDR=yes
fi

if [[ ! -d $(dirname "$IP_BLACKLIST") || ! -d $(dirname "$IP_BLACKLIST_RESTORE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST" "$IP_BLACKLIST_RESTORE"|sort -u)"
  exit 1
fi

# Directory for IPv6 files
if [[ ! -d $(dirname "$IP6_BLACKLIST") || ! -d $(dirname "$IP6_BLACKLIST_RESTORE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP6_BLACKLIST" "$IP6_BLACKLIST_RESTORE"|sort -u)"
  exit 1
fi

# Create IPv4 ipset if needed
if ! ipset list -n|command grep -q "$IPSET_BLACKLIST_NAME"; then
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: ipset does not exist yet, add it using:"
    echo >&2 "# ipset create $IPSET_BLACKLIST_NAME -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
    exit 1
  fi
  if ! ipset create "$IPSET_BLACKLIST_NAME" -exist hash:net family inet hashsize "${HASHSIZE:-16384}" maxelem "${MAXELEM:-65536}"; then
    echo >&2 "Error: while creating the initial ipset"
    exit 1
  fi
fi

# Create IPv6 ipset if needed
if ! ipset list -n|command grep -q "$IPSET6_BLACKLIST_NAME"; then
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: IPv6 ipset does not exist yet, add it using:"
    echo >&2 "# ipset create $IPSET6_BLACKLIST_NAME -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
    exit 1
  fi
  if ! ipset create "$IPSET6_BLACKLIST_NAME" -exist hash:net family inet6 hashsize "${HASHSIZE:-16384}" maxelem "${MAXELEM:-65536}"; then
    echo >&2 "Error: while creating the initial IPv6 ipset"
    exit 1
  fi
fi

# Create the IPv4 iptables binding if needed
if ! iptables -nvL INPUT|command grep -q "match-set $IPSET_BLACKLIST_NAME"; then
  # we may also have assumed that INPUT rule n°1 is about packets statistics (traffic monitoring)
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: iptables does not have the needed ipset INPUT rule, add it using:"
    echo >&2 "# iptables -I INPUT ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET_BLACKLIST_NAME src -j DROP"
    exit 1
  fi
  if ! iptables -I INPUT "${IPTABLES_IPSET_RULE_NUMBER:-1}" -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
    echo >&2 "Error: while adding the --match-set ipset rule to iptables"
    exit 1
  fi
fi

# Create the IPv6 ip6tables binding if needed
if ! ip6tables -nvL INPUT|command grep -q "match-set $IPSET6_BLACKLIST_NAME"; then
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: ip6tables does not have the needed ipset INPUT rule, add it using:"
    echo >&2 "# ip6tables -I INPUT ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET6_BLACKLIST_NAME src -j DROP"
    exit 1
  fi
  if ! ip6tables -I INPUT "${IPTABLES_IPSET_RULE_NUMBER:-1}" -m set --match-set "$IPSET6_BLACKLIST_NAME" src -j DROP; then
    echo >&2 "Error: while adding the --match-set ipset rule to ip6tables"
    exit 1
  fi
fi

# Process blacklists for both IPv4 and IPv6
IP_BLACKLIST_TMP=$(mktemp)
IP6_BLACKLIST_TMP=$(mktemp)

for i in "${BLACKLISTS[@]}"
do
  IP_TMP=$(mktemp)
  (( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i") ))
  if (( HTTP_RC == 200 || HTTP_RC == 302 || HTTP_RC == 0 )); then # "0" because file:/// returns 000
    # Extract IPv4 addresses
    command grep -Po '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$IP_TMP" | sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' >> "$IP_BLACKLIST_TMP"

    # Extract IPv6 addresses - Ensure they contain double colon (::) which is required in IPv6
    grep -o -E '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}::[0-9a-fA-F:]{0,32}(/[0-9]{1,3})?|::[0-9a-fA-F:]{0,32}(/[0-9]{1,3})?' "$IP_TMP" >> "$IP6_BLACKLIST_TMP"

    [[ ${VERBOSE:-yes} == yes ]] && echo -n "."
  elif (( HTTP_RC == 503 )); then
    echo -e "\\nUnavailable (${HTTP_RC}): $i"
  else
    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
  fi
  rm -f "$IP_TMP"
done

# Process IPv4 addresses
# sort -nu does not work as expected
sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' "$IP_BLACKLIST_TMP"|sort -n|sort -mu >| "$IP_BLACKLIST"
if [[ ${DO_OPTIMIZE_CIDR} == yes ]]; then
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo -e "\\nIPv4 addresses before CIDR optimization: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
  fi
  < "$IP_BLACKLIST" iprange --optimize - > "$IP_BLACKLIST_TMP" 2>/dev/null
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo "IPv4 addresses after CIDR optimization:  $(wc -l "$IP_BLACKLIST_TMP" | cut -d' ' -f1)"
  fi
  cp "$IP_BLACKLIST_TMP" "$IP_BLACKLIST"
fi

# Process IPv6 addresses - filter out private/special addresses
# Filter out:
# fe80::/10 (link-local)
# fc00::/7, fd00::/8 (unique local)
# ::1/128 (loopback)
# :: (unspecified)
# 2001:db8::/32 (documentation)
# ff00::/8 (multicast)
if [[ -s "$IP6_BLACKLIST_TMP" ]]; then
  cat "$IP6_BLACKLIST_TMP" | grep -v -E '^(fe80:|fc00:|fd00:|::1$|::$|2001:db8:|ff00:)' | sort -u >| "$IP6_BLACKLIST"
fi

rm -f "$IP_BLACKLIST_TMP" "$IP6_BLACKLIST_TMP"

# Create IPv4 ipset restore file
cat >| "$IP_BLACKLIST_RESTORE" <<EOF
create $IPSET_TMP_BLACKLIST_NAME -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
create $IPSET_BLACKLIST_NAME -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
EOF

# Add IPv4 addresses to restore file
sed -rn -e '/^#|^$/d' \
  -e "s/^([0-9./]+).*/add $IPSET_TMP_BLACKLIST_NAME \\1/p" "$IP_BLACKLIST" >> "$IP_BLACKLIST_RESTORE"

# Complete IPv4 ipset restore file
cat >> "$IP_BLACKLIST_RESTORE" <<EOF
swap $IPSET_BLACKLIST_NAME $IPSET_TMP_BLACKLIST_NAME
destroy $IPSET_TMP_BLACKLIST_NAME
EOF

# Create IPv6 ipset restore file
cat >| "$IP6_BLACKLIST_RESTORE" <<EOF
create $IPSET6_TMP_BLACKLIST_NAME -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
create $IPSET6_BLACKLIST_NAME -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
EOF

# Add IPv6 addresses to restore file - with validation to ensure they contain :: (double colon)
if [[ -s "$IP6_BLACKLIST" ]]; then
  while IFS= read -r line; do
    # Only include lines that contain double colon (::) which is required in IPv6
    if [[ "$line" == *::* ]]; then
      echo "add $IPSET6_TMP_BLACKLIST_NAME $line" >> "$IP6_BLACKLIST_RESTORE"
    fi
  done < "$IP6_BLACKLIST"
fi

# Complete IPv6 ipset restore file
cat >> "$IP6_BLACKLIST_RESTORE" <<EOF
swap $IPSET6_BLACKLIST_NAME $IPSET6_TMP_BLACKLIST_NAME
destroy $IPSET6_TMP_BLACKLIST_NAME
EOF

# Apply the ipset rules
ipset -file "$IP_BLACKLIST_RESTORE" restore
if [[ -s "$IP6_BLACKLIST" ]]; then
  ipset -file "$IP6_BLACKLIST_RESTORE" restore
fi

if [[ ${VERBOSE:-no} == yes ]]; then
  echo
  echo "IPv4 blacklisted addresses found: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
  echo "IPv6 blacklisted addresses found: $(wc -l "$IP6_BLACKLIST" | cut -d' ' -f1)"
fi
