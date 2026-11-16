#!/bin/bash
# usage: run_all.sh <label> <analyzer> <root> <port-base>
label=$1; analyzer=$2; root=$3; port=$4
mkdir -p /tmp/upx32/dumps-$label "$root/filesys/c/upx"
cd /tmp/upx32-tools
while read h l; do
  short=${h:0:8}
  cp /tmp/upx32/samples/$h "$root/filesys/c/upx/$short.exe"
  port=$((port+1))
  perl -e 'alarm 300; exec @ARGV' uv run -q --with pefile python unpack_gdb.py /tmp/upx32/samples/$h \
    --analyzer "$analyzer" --root "$root" --guest "c:\\upx\\$short.exe" --truth ~/.cache/upx32/out/$h \
    --out /tmp/upx32/dumps-$label/$h --steps-after 200 --port $port || echo "{\"sample\": \"$h\", \"error\": \"driver killed\"}"
done < /tmp/upx32/hashes.txt
