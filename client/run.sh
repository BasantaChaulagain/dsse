# strings_h=('aa' 'ab' 'ac' 'ad' 'ae' 'af' 'ag' 'ah' 'ai' 'aj' 'ak' 'al' 'am' 'an' 'ao' 'ap' 'aq' 'ar' 'as' 'at' 'au' 'av' 'aw' 'ax' 'ay')
strings_h=('an' 'ao' 'ap' 'aq' 'ar')
strings_5=('fx' 'fy' 'fz' 'ga' 'gb' 'gc' 'gd' 'ge')
# strings_5=('hg' 'hh' 'hi' 'hj' 'hk' 'hl')
# strings_5=('ha' 'hb' 'hc' 'hd' 'he' 'hf' 'hg' 'hh' 'hi' 'hj' 'hk' 'hl' 'hm' 'hn' 'ho' 'hp' 'hq' 'hr' 'hs' 'ht' 'hu' 'hv' 'hw' 'hx' 'hy')
# strings_5=('aa' 'ab' 'ac' 'ad' 'ae' 'af' 'ag' 'ah' 'ai' 'aj' 'ak' 'al' 'am' 'an' 'ao' 'ap' 'aq' 'ar' 'as' 'at' 'au' 'av' 'aw' 'ax' 'ay' 'az' 'ba' 'bb' 'bc' 'bd' 'be' 'bf' 'bg' 'bh' 'bi' 'bj' 'bk' 'bl' 'bm' 'bn' 'bo' 'bp' 'bq' 'br' 'bs' 'bt' 'bu' 'bv' 'bw' 'bx' 'by' 'bz' 'ca' 'cb' 'cc' 'cd' 'ce' 'cf' 'cg' 'ch' 'ci' 'cj' 'ck' 'cl' 'cm' 'cn' 'co' 'cp' 'cq' 'cr' 'cs' 'ct' 'cu' 'cv' 'cw' 'cx' 'cy' 'cz' 'da' 'db' 'dc' 'dd' 'de' 'df' 'dg' 'dh' 'di' 'dj' 'dk' 'dl' 'dm' 'dn' 'do' 'dp' 'dq' 'dr' 'ds' 'dt' 'du' 'dv' 'dw' 'dx' 'dy' 'dz' 'ea' 'eb' 'ec' 'ed' 'ee' 'ef' 'eg' 'eh' 'ei' 'ej' 'ek' 'el' 'em' 'en' 'eo' 'ep' 'eq' 'er' 'es' 'et' 'eu' 'ev' 'ew' 'ex' 'ey' 'ez' 'fa' 'fb' 'fc' 'fd' 'fe' 'ff' 'fg' 'fh' 'fi' 'fj' 'fk' 'fl' 'fm' 'fn' 'fo' 'fp' 'fq' 'fr' 'fs' 'ft' 'fu' 'fv' 'fw' 'fx' 'fy' 'fz' 'ga' 'gb' 'gc' 'gd' 'ge' 'gf' 'gg' 'gh' 'gi' 'gj' 'gk' 'gl' 'gm' 'gn' 'go' 'gp' 'gq' 'gr' 'gs' 'gt' 'gu' 'gv' 'gw' 'gx' 'gy' 'gz' 'ha' 'hb' 'hc' 'hd' 'he' 'hf' 'hg' 'hh' 'hi' 'hj' 'hk' 'hl' 'hm' 'hn' 'ho' 'hp' 'hq' 'hr' 'hs' 'ht' 'hu' 'hv' 'hw' 'hx' 'hy' 'hz' 'ia' 'ib' 'ic' 'id' 'ie' 'if' 'ig' 'ih' 'ii' 'ij' 'ik' 'il' 'im' 'in' 'io' 'ip' 'iq' 'ir' 'is' 'it' 'iu' 'iv' 'iw' 'ix' 'iy' 'iz' 'ja' 'jb' 'jc' 'jd' 'je' 'jf' 'jg' 'jh' 'ji' 'jj' 'jk' 'jl' 'jm' 'jn' 'jo' 'jp' 'jq' 'jr' 'js' 'jt' 'ju' 'jv' 'jw' 'jx' 'jy' 'jz' 'ka' 'kb' 'kc' 'kd' 'ke' 'kf' 'kg' 'kh' 'ki' 'kj' 'kk' 'kl' 'km' 'kn' 'ko' 'kp' 'kq' 'kr' 'ks' 'kt' 'ku' 'kv' 'kw' 'kx' 'ky' 'kz' 'la' 'lb' 'lc')


## -------------------
echo "light server - d"

for k in 8 10 12 14; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
	for c in 5 10 20 30; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		python client.py -u orig/light_server/li_d |& tee out_light/d/li_d_${k}k_${c}.txt
		cp -r ltdict out_light/d/ltdict_li_d_${k}k_${c}
		cp -r vdict out_light/d/vdict_li_d_${k}k_${c}
		cp -r ../server/indexes ../server/out_light/d/indexes_li_d_${k}k_${c}
		cp -r ../server/enc ../server/out_light/d/enc_li_d_${k}k_${c}
		cp metadata out_light/d/metadata_li_d_${k}k_${c}
	done
done

echo "light server - h"
for k in 8 10 12 14; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 5 10 20 30 40; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
        for x in "${strings_h[@]}"; do
		    python client.py -u orig/light_server/li_h_${x} |& tee out_light/h/li_h_${x}_${k}k_${c}.txt
		done
        cp -r ltdict out_light/h/ltdict_li_h_${k}k_${c}
		cp -r vdict out_light/h/vdict_li_h_${k}k_${c}
		cp -r ../server/indexes ../server/out_light/h/indexes_li_h_${k}k_${c}
		cp -r ../server/enc ../server/out_light/h/enc_li_h_${k}k_${c}
		cp metadata out_light/h/metadata_li_h_${k}k_${c}
	done
done

echo "light server - 5"
for k in 8 10 12 14; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 5 10 20 30 40; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		for x in "${strings_5[@]}"; do
		    python client.py -u orig/light_server/li_5_${x} |& tee out_light/5/li_5_${x}_${k}k_${c}.txt
		done
		cp -r ltdict out_light/5/ltdict_li_5_${k}k_${c}
		cp -r vdict out_light/5/vdict_li_5_${k}k_${c}
		cp -r ../server/indexes ../server/out_light/5/indexes_li_5_${k}k_${c}
		cp -r ../server/enc ../server/out_light/5/enc_li_5_${k}k_${c}
		cp metadata out_light/5/metadata_li_5_${k}k_${c}
	done
done


# -------------------------------
echo "heavy server - d"

for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		python client.py -u orig/heavy_server/hv_d |& tee out_heavy/d/hv_d_${k}k_${c}.txt
		cp -r ltdict out_heavy/d/ltdict_hv_d_${k}k_${c}
		cp -r vdict out_heavy/d/vdict_hv_d_${k}k_${c}
		cp -r ../server/indexes ../server/out_heavy/d/indexes_hv_d_${k}k_${c}
		cp -r ../server/enc ../server/out_heavy/d/enc_hv_d_${k}k_${c}
		cp metadata out_heavy/d/metadata_hv_d_${k}k_${c}
	done
done

echo "heavy server - h"
for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
        for x in "${strings_h[@]}"; do
		    python client.py -u orig/heavy_server/hv_h_${x} |& tee out_heavy/h/hv_h_${x}_${k}k_${c}.txt
		done
        cp -r ltdict out_heavy/h/ltdict_hv_h_${k}k_${c}
		cp -r vdict out_heavy/h/vdict_hv_h_${k}k_${c}
		cp -r ../server/indexes ../server/out_heavy/h/indexes_hv_h_${k}k_${c}
		cp -r ../server/enc ../server/out_heavy/h/enc_hv_h_${k}k_${c}
		cp metadata out_heavy/h/metadata_hv_h_${k}k_${c}
	done
done

echo "heavy server - 5"
for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		for x in "${strings_5[@]}"; do
		    python client.py -u orig/heavy_server/hv_5_${x} |& tee out_heavy/5/hv_5_${x}_${k}k_${c}.txt
		done
		cp -r ltdict out_heavy/5/ltdict_hv_5_${k}k_${c}
		cp -r vdict out_heavy/5/vdict_hv_5_${k}k_${c}
		cp -r ../server/indexes ../server/out_heavy/5/indexes_hv_5_${k}k_${c}
		cp -r ../server/enc ../server/out_heavy/5/enc_hv_5_${k}k_${c}
		cp metadata out_heavy/5/metadata_hv_5_${k}k_${c}
	done
done


# -------------------------------
echo "extreme server - d"

for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		python client.py -u orig/extreme_server/ex_d |& tee out_extreme/d/ex_d_${k}k_${c}.txt
		cp -r ltdict out_extreme/d/ltdict_ex_d_${k}k_${c}
		cp -r vdict out_extreme/d/vdict_ex_d_${k}k_${c}
		cp -r ../server/indexes ../server/out_extreme/d/indexes_ex_d_${k}k_${c}
		cp -r ../server/enc ../server/out_extreme/d/enc_ex_d_${k}k_${c}
		cp metadata out_extreme/d/metadata_ex_d_${k}k_${c}
	done
done

echo "extreme server - h"
for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
        for x in "${strings_h[@]}"; do
		    python client.py -u orig/extreme_server/ex_h_${x} |& tee out_extreme/h/ex_h_${x}_${k}k_${c}.txt
		done
        cp -r ltdict out_extreme/h/ltdict_ex_h_${k}k_${c}
		cp -r vdict out_extreme/h/vdict_ex_h_${k}k_${c}
		cp -r ../server/indexes ../server/out_extreme/h/indexes_ex_h_${k}k_${c}
		cp -r ../server/enc ../server/out_extreme/h/enc_ex_h_${k}k_${c}
		cp metadata out_extreme/h/metadata_ex_h_${k}k_${c}
	done
done

echo "extreme server - 5"
for k in 6 8 10 12; do
	sed -i "s/num_of_logs = [[:digit:]]\+/num_of_logs = ${k}000/g" config.ini
    for c in 20 30 40 50; do
		sed -i "s/num_of_segments = [[:digit:]]\+/num_of_segments = ${c}/g" config.ini

		./clean.sh
		for x in "${strings_5[@]}"; do
		    python client.py -u orig/extreme_server/ex_5_${x} |& tee out_extreme/5/ex_5_${x}_${k}k_${c}.txt
		done
		cp -r ltdict out_extreme/5/ltdict_ex_5_${k}k_${c}
		cp -r vdict out_extreme/5/vdict_ex_5_${k}k_${c}
		cp -r ../server/indexes ../server/out_extreme/5/indexes_ex_5_${k}k_${c}
		cp -r ../server/enc ../server/out_extreme/5/enc_ex_5_${k}k_${c}
		cp metadata out_extreme/5/metadata_ex_5_${k}k_${c}
	done
done


# -------------------------------

# for p in 1 2 3 4 5 6 7 8 9 10; do
#     ./clean.sh
#     python client.py -u orig/ingestion_perf/part${p}.csv |& tee ingestion_perf/out_${p}g.txt
#     cp -r ltdict ingestion_perf/ltdict_${p}g
#     cp -r vdict ingestion_perf/vdict_${p}g
#     cp -r ../server/enc ../server/ingestion_perf/enc_${p}g
#     cp metadata ingestion_perf/metadata_${p}g	
# done

# for p in 10 9 8 7 6 5 4 3 2 1; do
#     ./clean.sh
#     python client.py -u orig/ingestion_perf/part${p}.csv |& tee ingestion_perf/out_${p}g_1cg.txt
#     cp -r ltdict ingestion_perf/ltdict_${p}g_1cg
#     cp -r vdict ingestion_perf/vdict_${p}g_1cg
#     cp -r ../server/enc ../server/ingestion_perf/enc_${p}g_1cg
#     cp metadata ingestion_perf/metadata_${p}g_1cg
# done
