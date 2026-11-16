#!/bin/bash
# usage: ida_batch.sh <label> <heuristic>; SOGEN_ANALYZER/SOGEN_ROOT select the build
label=$1; heur=$2
source /tmp/upx32-tools/env.sh
out=/tmp/upx32/ida-$label; mkdir -p $out
while read sha name; do
  short=${sha:0:8}
  d=$out/$short-$heur; rm -rf $d; mkdir -p $d
  cp /tmp/upx32/samples/$sha $d/$short.exe
  start=$(date +%s)
  (cd $d && perl -e 'alarm 400; exec @ARGV' python ~/code/hex-rays/malware-extensions/ida-unpacker-framework/unpack_one.py $short.exe -b sogen --heuristic $heur -f -r report.json -v > run.log 2>&1)
  rc=$?
  python3 -c "import json,sys;r=json.load(open('$d/report.json')) if __import__('os').path.exists('$d/report.json') else {};print(json.dumps({'label':'$label','heur':'$heur','sample':'$short','rc':$rc,'s':$(date +%s)-$start,'oep':r.get('oep'),'oep_ea':hex(r['oep_ea']) if r.get('oep_ea') else None,'funcs':r.get('functions'),'imports':r.get('imports'),'ok':r.get('ok')}))" | tee -a /tmp/upx32/ida-results.jsonl
done < /tmp/upx32/hashes.txt
