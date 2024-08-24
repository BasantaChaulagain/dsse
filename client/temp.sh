# mode 2
sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = 12000/g" config.ini
sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = 10/g" config.ini

# for k in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
for k in 1 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30; do
    echo "part = ${k}" >> out_dsse.txt
    ./clean.sh
    python client.py -u orig/ingestion_perf/part${k}.csv >> out_dsse.txt

    cp -r ltdict sse_dsse/dsse/ltdict_${k}g
    cp -r vdict sse_dsse/dsse/vdict_${k}g
    cp -r ../server/indexes ../server/sse_dsse/dsse/indexes_${k}g
    cp -r ../server/enc ../server/sse_dsse/dsse/enc_${k}g
    cp metadata sse_dsse/dsse/metadata_${k}g
done

#mode 0
# for k in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
#     echo "part = ${k}" >> out_mode0.txt
#     ./clean.sh
#     python client.py -u orig/ingestion_perf/part${k}.csv >> out_mode0.txt

#     cp -r ltdict sse_dsse/mode0/ltdict_${k}g
#     cp -r vdict sse_dsse/mode0/vdict_${k}g
#     cp -r ../server/enc ../server/sse_dsse/mode0/enc_${k}g
#     cp metadata sse_dsse/mode0/metadata_${k}g
# done