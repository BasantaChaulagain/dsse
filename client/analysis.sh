echo "daily ingestion:" > out_light.txt
for k in 8 10 12 14; do
	for c in 5 10 20 30; do
        ./clean.sh
        sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
        sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
        cp out_light/d/ltdict_li_d_${k}k_${c}/* ltdict/
        cp out_light/d/vdict_li_d_${k}k_${c}/* vdict/
        cp out_light/d/metadata_li_d_${k}k_${c} metadata
        cp ../server/out_light/d/indexes_li_d_${k}k_${c}/* ../server/indexes
        cp ../server/out_light/d/enc_li_d_${k}k_${c}/* ../server/enc
        echo "${k}k_${c} loaded." >> out_light.txt

        # echo '2'  | ./AUDIT_bt -t li_d_init_table.dat -f 23464152 >> out_light.txt
        ./AUDIT_bt -t li_d_init_table.dat -f 25165885 >> out_light.txt
        ./AUDIT_ft -t li_d_init_table.dat -f 34123 >> out_light.txt
        echo -e '\n\n\n' >> out_light.txt
    done
done

echo "-----------------------------------" >> out_light.txt
echo "-----------------------------------" >> out_light.txt
echo "-----------------------------------" >> out_light.txt

echo "hourly ingestion:" >> out_light.txt
for k in 8 10 12 14; do
	for c in 5 10 20 30; do
        ./clean.sh
        sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
        sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
        cp out_light/h/ltdict_li_h_${k}k_${c}/* ltdict/
        cp out_light/h/vdict_li_h_${k}k_${c}/* vdict/
        cp out_light/h/metadata_li_h_${k}k_${c} metadata
        cp ../server/out_light/h/indexes_li_h_${k}k_${c}/* ../server/indexes
        cp ../server/out_light/h/enc_li_h_${k}k_${c}/* ../server/enc
        echo "${k}k_${c} loaded." >> out_light.txt

        ./AUDIT_bt -t li_d_init_table.dat -f 25165885 >> out_light.txt
        ./AUDIT_ft -t li_d_init_table.dat -f 34123 >> out_light.txt
        echo -e '\n\n\n' >> out_light.txt
    done
done

echo "-----------------------------------" >> out_light.txt
echo "-----------------------------------" >> out_light.txt
echo "-----------------------------------" >> out_light.txt

echo "realtime ingestion:" >> out_light.txt
for k in 8 10 12 14; do
	for c in 5 10 20 30; do
        ./clean.sh
        sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
        sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
        cp out_light/5/ltdict_li_5_${k}k_${c}/* ltdict/
        cp out_light/5/vdict_li_5_${k}k_${c}/* vdict/
        cp out_light/5/metadata_li_5_${k}k_${c} metadata
        cp ../server/out_light/5/indexes_li_5_${k}k_${c}/* ../server/indexes
        cp ../server/out_light/5/enc_li_5_${k}k_${c}/* ../server/enc
        echo "${k}k_${c} loaded." >> out_light.txt

        ./AUDIT_bt -t li_d_init_table.dat -f 25165885 >> out_light.txt
        ./AUDIT_ft -t li_d_init_table.dat -f 34123 >> out_light.txt
        echo -e '\n\n\n' >> out_light.txt
    done
done


# echo "daily ingestion:" > out_heavy.txt
# for k in 6 8 10 12; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_heavy/d/ltdict_hv_d_${k}k_${c}/* ltdict/
#         cp out_heavy/d/vdict_hv_d_${k}k_${c}/* vdict/
#         cp out_heavy/d/metadata_hv_d_${k}k_${c} metadata
#         cp ../server/out_heavy/d/indexes_hv_d_${k}k_${c}/* ../server/indexes
#         cp ../server/out_heavy/d/enc_hv_d_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_heavy.txt

#         ./AUDIT_ft -t hv_d_init_table.dat -f 34010 >> out_heavy.txt
#         echo -e '\n\n\n' >> out_heavy.txt
#     done
# done

# echo "-----------------------------------" >> out_heavy.txt
# echo "-----------------------------------" >> out_heavy.txt
# echo "-----------------------------------" >> out_heavy.txt

# echo "hourly ingestion:" >> out_heavy.txt
# for k in 6 8 10 12; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_heavy/h/ltdict_hv_h_${k}k_${c}/* ltdict/
#         cp out_heavy/h/vdict_hv_h_${k}k_${c}/* vdict/
#         cp out_heavy/h/metadata_hv_h_${k}k_${c} metadata
#         cp ../server/out_heavy/h/indexes_hv_h_${k}k_${c}/* ../server/indexes
#         cp ../server/out_heavy/h/enc_hv_h_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_heavy.txt

#         ./AUDIT_ft -t hv_d_init_table.dat -f 34010 >> out_heavy.txt
#         echo -e '\n\n\n' >> out_heavy.txt
#     done
# done

# echo "-----------------------------------" >> out_heavy.txt
# echo "-----------------------------------" >> out_heavy.txt
# echo "-----------------------------------" >> out_heavy.txt

# echo "realtime ingestion:" >> out_heavy.txt
# for k in 6 8 10 12; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_heavy/5/ltdict_hv_5_${k}k_${c}/* ltdict/
#         cp out_heavy/5/vdict_hv_5_${k}k_${c}/* vdict/
#         cp out_heavy/5/metadata_hv_5_${k}k_${c} metadata
#         cp ../server/out_heavy/5/indexes_hv_5_${k}k_${c}/* ../server/indexes
#         cp ../server/out_heavy/5/enc_hv_5_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_heavy.txt

#         ./AUDIT_ft -t hv_d_init_table.dat -f 34010 >> out_heavy.txt
#         echo -e '\n\n\n' >> out_heavy.txt
#     done
# done



# echo "daily ingestion:" >> out_extreme.txt
# # for k in 6 8 10 12; do
# for k in 6; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_extreme/d/ltdict_ex_d_${k}k_${c}/* ltdict/
#         cp out_extreme/d/vdict_ex_d_${k}k_${c}/* vdict/
#         cp out_extreme/d/metadata_ex_d_${k}k_${c} metadata
#         cp ../server/out_extreme/d/indexes_ex_d_${k}k_${c}/* ../server/indexes
#         cp ../server/out_extreme/d/enc_ex_d_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_extreme.txt

#         echo '34' | ./AUDIT_bt -t ex_d_init_table.dat -f 25165885 >> out_extreme.txt
#         # ./AUDIT_ft -t ex_d_init_table.dat -f 34010 >> out_extreme.txt
#         echo -e '\n\n\n' >> out_extreme.txt
#     done
# done

# echo "-----------------------------------" >> out_extreme.txt
# echo "-----------------------------------" >> out_extreme.txt
# echo "-----------------------------------" >> out_extreme.txt

# echo "hourly ingestion:" >> out_extreme.txt
# # for k in 6 8 10 12; do
# for k in 6; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_extreme/h/ltdict_ex_h_${k}k_${c}/* ltdict/
#         cp out_extreme/h/vdict_ex_h_${k}k_${c}/* vdict/
#         cp out_extreme/h/metadata_ex_h_${k}k_${c} metadata
#         cp ../server/out_extreme/h/indexes_ex_h_${k}k_${c}/* ../server/indexes
#         cp ../server/out_extreme/h/enc_ex_h_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_extreme.txt

#         echo '34' | ./AUDIT_bt -t ex_d_init_table.dat -f 25165885 >> out_extreme.txt
#         # ./AUDIT_ft -t ex_d_init_table.dat -f 34010 >> out_extreme.txt
#         echo -e '\n\n\n' >> out_extreme.txt
#     done
# done

# echo "-----------------------------------" >> out_extreme.txt
# echo "-----------------------------------" >> out_extreme.txt
# echo "-----------------------------------" >> out_extreme.txt

# echo "realtime ingestion:" >> out_extreme.txt
# # for k in 6 8 10 12; do
# for k in 6; do
# 	for c in 20 30 40 50; do
#         ./clean.sh
#         sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
#         sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini
#         cp out_extreme/5/ltdict_ex_5_${k}k_${c}/* ltdict/
#         cp out_extreme/5/vdict_ex_5_${k}k_${c}/* vdict/
#         cp out_extreme/5/metadata_ex_5_${k}k_${c} metadata
#         cp ../server/out_extreme/5/indexes_ex_5_${k}k_${c}/* ../server/indexes
#         cp ../server/out_extreme/5/enc_ex_5_${k}k_${c}/* ../server/enc
#         echo "${k}k_${c} loaded." >> out_extreme.txt
        
#         echo '34' | ./AUDIT_bt -t ex_d_init_table.dat -f 25165885 >> out_extreme.txt
#         # ./AUDIT_ft -t ex_d_init_table.dat -f 34010 >> out_extreme.txt
#         echo -e '\n\n\n' >> out_extreme.txt
#     done
# done