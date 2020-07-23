#!/bin/bash

DOWNLOAD_DIR="./databases"
mkdir -p $DOWNLOAD_DIR

function download {
  name=$(echo $1 |awk -F "/" '{print $NF}')
  echo "Downloading $name..."
  wget -O "$DOWNLOAD_DIR/$name" "$1"
}

# AfriNIC
download "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz"

# APNIC
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz"
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz"
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.route-set.gz"
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.route.gz"
download "https://ftp.apnic.net/pub/apnic/whois/apnic.db.route6.gz"

# LACNIC
download "http://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz"

# RIPE-NCC
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route-set.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz"
download "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route6.gz"

# http://irr.net/docs/list.html
# Most on that list either no longer exist or are too outdated
download "https://ftp.arin.net/pub/rr/arin.db.gz"
download "https://ftp.arin.net/pub/rr/arin-nonauth.db.gz"
download "ftp://rr.level3.net/pub/rr/level3.db.gz"
download "ftp://rr1.ntt.net/nttcomRR/nttcom.db.gz"
download "ftp://ftp.radb.net/radb/dbase/radb.db.gz"
download "ftp://ftp.bgp.net.br/dbase/tc.db.gz"

# If you have a valid API key from ARIN, then you can download the full WHOIS 
# database dump. Use "export ARIN_API_KEY=<KEY>" before running this script.
if [[ ! -v ARIN_API_KEY ]]; then
  exit
elif [ -z "$ARIN_API_KEY" ]; then
  exit
else
  echo "ARIN API key detected. Downloading non-public WHOIS dump file..."
  echo -e "\e[31mWARNING: DO NOT RELEASE ANY FILES FROM 'arin_db.zip' UNDER ANY CIRCUMSTANCES!\e[0m"

  # Make a temp directory
  mkdir arin_db/

  # Make wget quiet so it doesn't echo the API key to stdout
  wget -q --show-progress -O "arin_db.zip" "https://accountws.arin.net/public/secure/downloads/bulkwhois?apikey=$ARIN_API_KEY"

  # Need to have unzip installed
  unzip "arin_db.zip" -d "arin_db/"

  # Move/cleanup
  mv "arin_db/arin_db.txt" $DOWNLOAD_DIR/
  rm -rf "arin_db/" "arin_db.zip"
fi
