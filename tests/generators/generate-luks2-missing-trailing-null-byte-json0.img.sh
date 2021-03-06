#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with well-formed json but missing
# trailing null byte.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

PATTERN="\"config\":{"
KEY="\"config_key\":\""

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d tmp || mkdir tmp
	read_luks2_json0 $TGT_IMG tmp/json0
	read_luks2_bin_hdr0 $TGT_IMG tmp/hdr0
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr1
}

function generate()
{
	read -r json_str < tmp/json0
	json_len=${#json_str}
	pindex=$(strindex $json_str $PATTERN)
	test $pindex -gt 0 || exit 2

	offset=${#PATTERN}
	offset=$((offset+pindex))
	key_len=${#KEY}
	remain=$((LUKS2_JSON_SIZE*512-key_len-json_len-1)) # -1: closing '"'
	if [ ${json_str:offset:1} = "}" ]; then
		format_str="%s%s%s"
	else
		format_str="%s%s,%s"
		remain=$((remain-1)) # also count with separating ','
	fi
	test $remain -gt 0 || exit 2

	fill=$(repeat_str "X" $remain)
	fill=$(repeat_str "X" $remain)"\""

	printf $format_str $KEY $fill ${json_str:$offset} | _dd of=tmp/json0 bs=1 seek=$offset conv=notrunc

	merge_bin_hdr_with_json tmp/hdr0 tmp/json0 tmp/area0
	erase_checksum tmp/area0
	chks0=$(calc_sha256_checksum_file tmp/area0)
	write_checksum $chks0 tmp/area0
	write_luks2_hdr0 tmp/area0 $TGT_IMG
	kill_bin_hdr tmp/hdr1
	write_luks2_hdr1 tmp/hdr1 $TGT_IMG
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr_res1
	local str_res1=$(head -c 6 tmp/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2

	read_luks2_json0 $TGT_IMG tmp/json_res0
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2
	read -r json_str_res0 < tmp/json_res0
	test ${#json_str_res0} -eq $((LUKS2_JSON_SIZE*512)) || exit 2
}

function cleanup()
{
	rm -f tmp/*
}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
cleanup
