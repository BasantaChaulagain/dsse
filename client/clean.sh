rm metadata

rm ../server/enc/*
# rm ../server/indexes/*

# echo {} > ltdict.json
# echo {} > vdict.json

rm vdict/*
rm ltdict/*

# for file in ltdict/ltdict_cg* vdict/vdict_cg*; do
#     echo '{}' > "$file"
# done

sed -i "s/last_segment_id = [[:digit:]]\+/last_segment_id = 0/g" config.ini

echo "Cleaning Successful!"