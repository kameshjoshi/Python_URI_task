#!/usr/bin/env python
# encoding: utf-8



import re

URI_REGEX = re.compile(
        r'^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?')


DEC_OCTET   = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
UNRESERVED  = r'[A-Za-z0-9\-\.\_\~]'
GEN_DELIMS  = r'[\:\/\?\#\[\]\@]'
SUB_DELIMS  = r"[\!\$\&\'\(\)\*\+\,\;\=]"

USERINFO_REGEX = re.compile(r'|'.join([UNRESERVED, SUB_DELIMS, r'[\:]']))
IPV4_REGEX = re.compile(r'\.'.join([DEC_OCTET] * 4))
IPVLITERAL_REGEX = re.compile(r"(?:[[0-9A-Za-z\:]+])")
REG_NAME_SEARCH_REGEX = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=%])*")
REG_NAME_ELIGIBLE_REGEX = re.compile(r'|'.join([UNRESERVED, SUB_DELIMS]))

PCHAR = '|'.join([UNRESERVED, SUB_DELIMS, r'[\:\@]'])

PATH_REGEX = re.compile(PCHAR)
PATH_NOSCHEME_REGEX = re.compile('|'.join([PCHAR, SUB_DELIMS, r'[\@]']))

# Just "allow" unreserved/sub-delims/:/@/, functions will pct-encode
# everything else
QUERY_REGEX = re.compile('|'.join([PCHAR, r'[\/\?]']))
FRAGMENT_REGEX = re.compile('|'.join([PCHAR, r'[\/\?]']))
