#!/bin/bash

DOWNLOAD_DIR="./databases"
mkdir -p $DOWNLOAD_DIR

function download {
  name=$(echo $1 |awk -F "/" '{print $NF}')
  echo "Downloading $name..."
  wget -O "$DOWNLOAD_DIR/$name" "$1"
}

download "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz"

download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz"
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz"

download "http://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz"

download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"

# ARIN does not publish a raw WHOIS database like the other registrars,
# instead they publish routing data as part of the IRR program. This data
# is similar but not equivalent to the WHOIS database and more importantly,
# the format is distinct from the one implemented in `create_db.py`, ARIN's 
# data is a dump in RPSL (Routing Policy Specification Language) defined in 
# RFC 2622.
#
# Objects of particular interest are the "route", "route6" and "route-set" 
# objects which define IP routes that are used, in a small way, to help provide 
# routing for the public Internet in conjunction with the BGP protocol: 
#
# https://tools.ietf.org/html/rfc2622#page-12
#
# download "https://ftp.arin.net/pub/rr/arin.db.gz"
# download "https://ftp.arin.net/pub/rr/arin-nonauth.db.gz"
