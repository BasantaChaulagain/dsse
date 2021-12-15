#!/bin/bash

UPDATE='python sse_client.py -u'
SEARCH='python sse_client.py -s'

# 22 files to UPDATE
FILES=('1.' '12.' '15.' '18.' '20.' '23.' '26.' '29.' '31.' '34.' '37.' '4.' '42.' '45.' '62.' '65.' '68.' '70.' '73.' '78.' '83.' '86.')

# 10 'known' terms
TERMS=( 'tuesday' 'such' 'pm' 'message' 'if' 'but' 'very' 'problem' 'see' 'the')

# 5 'unknown' terms
UNKNOWN=('beluga' 'whippersnapper' 'cufflink' 'grigsby' 'described')

if [ "$1" == "" ]; then
    echo -e "Must supply a command-line option!\n"
    echo -e "\t'update' (clears and updates indices with new messages)"
    echo -e "\t'search' (searches documents for a number of terms)"
    echo -e "\t'searchfull' (includes terms that will not be found)"
    echo -e "\t'all' (update and search)"
    exit 1
fi

if [ "$1" == "update" ] || [ "$1" == "all" ];then
    rm index*
    rm ../server/index
    for i in "${FILES[@]}"; do
        echo "$UPDATE inbox/$i"
        $UPDATE inbox/$i
    done
fi
if [ "$1" == "search" ] || [ "$1" == "all" ]; then
    #$SEARCH 'tuesday such pm message if but very problem see the'
    for i in "${TERMS[@]}"; do
        echo "$SEARCH $i"
        $SEARCH $i
    done
fi
if [ "$1" == "searchfull" ]; then
    for i in "${UNKNOWN[@]}"; do
        echo "$SEARCH $i";
        $SEARCH $i
    done
fi
