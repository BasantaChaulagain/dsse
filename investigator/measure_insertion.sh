times=100000

echo "pid cpu% mem% vsz rss">stat_client.out
echo "pid cpu% mem% vsz rss">stat_server.out
for i in $(seq 1 $times)
do
    OUTPUT=$(ps aux -y | grep "python client.py -u" | awk '{print $2,$3,$4,$5,$6}')
    echo -e "$OUTPUT" | head -1 >> stat_client.out
    sleep 50
done
