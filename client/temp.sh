# for k in 3 5 7 9 11 13 15 17 19 21 23 25 27 29; do
for k in 25 27 29; do
    echo "part = ${k}" >> out.txt
    ./clean.sh
    python client.py -u orig/ingestion_perf/part${k}.csv >> out.txt

    cp -r ltdict sse_dsse/dsse/ltdict_${k}g
    cp -r vdict sse_dsse/dsse/vdict_${k}g
    cp -r ../server/enc ../server/sse_dsse/dsse/enc_${k}g
    cp metadata sse_dsse/dsse/metadata_${k}g
done