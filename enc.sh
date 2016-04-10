#!/bin/bash
if [ $# -ne 3 ] ; then
	echo "Usage: ${0} password inputFile outputFile"
	exit 0
fi
PASSWORD=${1}
shift
IN=${1}
shift
OUT=${1}
#echo ${IN} ${OUT} ${PASSWORD}
IV=`openssl rand 8`
IV_TXT=`echo -n ${IV} | xxd -p` 
SHA=`shasum -a 256 ${IN} | head -c 64 | xxd -r -p`
echo -n ${IV} > ${OUT}
openssl enc -des-ede-cbc -in ${IN} -iv ${IV_TXT} -md md5 -k ${PASSWORD} -nosalt >> ${OUT}
echo -n ${SHA} >> ${OUT}
