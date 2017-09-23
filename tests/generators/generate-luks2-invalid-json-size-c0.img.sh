#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with invalid json_size in config section
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

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
	JS=$(((LUKS2_HDR_SIZE-LUKS2_BIN_HDR_SIZE)*512+4096))
	json_str=$(jq -c --arg js $JS '.config.json_size = ($js | tostring)' tmp/json0)
	test -n "$json_str" || exit 2
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" tmp/json0

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
	jq -c --arg js $JS 'if .config.json_size != ($js | tostring )
	       then error("Unexpected value in result json") else empty end' tmp/json_res0 || exit 5
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
