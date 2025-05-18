#!/usr/bin/python3
import sys
from utils import *

if sys.argv[1] in ['srl_retail2dev', 'cia_dev2retail', 'cia_retail2dev', 'cci_dev2retail', 'cci_retail2dev', 'csu2retailcias']:
    path = sys.argv[2]
    out = ''
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
    eval(sys.argv[1])(path, out)

elif sys.argv[1] in ['ncch_extractall', 'ncch_rebuildall', 'cci_extractall', 'cci_rebuildall', 'cia_extractall', 'cia_rebuildall']:
    path = sys.argv[2]
    dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--dev':
            dev = 1
    eval(sys.argv[1])(path, dev)

elif sys.argv[1] == 'cci2cia':
    path = sys.argv[2]
    out = ''
    cci_dev = cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--cci-dev':
            cci_dev = 1
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cci2cia(path, out, cci_dev, cia_dev)

elif sys.argv[1] == 'cdn2cia':
    path = sys.argv[2]
    out = ''
    title_ver = ''
    cdn_dev = cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--title-ver':
            title_ver = sys.argv[i + 1]
        elif sys.argv[i] == '--cdn-dev':
            cdn_dev = 1
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cdn2cia(path, out, title_ver, cdn_dev, cia_dev)

elif sys.argv[1] == 'cia2cdn':
    path = sys.argv[2]
    out = ''
    titlekey = ''
    cia_dev = 0
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--out':
            out = sys.argv[i + 1]
        elif sys.argv[i] == '--titlekey':
            titlekey = sys.argv[i + 1]
        elif sys.argv[i] == '--cia-dev':
            cia_dev = 1
    cia2cdn(path, out, titlekey, cia_dev)

elif sys.argv[1] == 'help' or sys.argv < 2:
    print("To run this script, you need to provide arguments.")
    print("Here is a list of arguments and examples for each one.")
    print("")
    print("Re-sign and re-encrypt NTR/TWL-enhanced/TWL-exclusive SRL for dev:")
    print("python3 ntool.py srl_retail2dev <path_to_srl> (--out <path_to_output_file>)")
    print("")
    print("Re-sign and re-encrypt CIA/CCI for retail/dev:")
    print("python3 ntool.py cia_dev2retail <path_to_cia> (--out <path_to_output_file>)")
    print("python3 ntool.py cia_retail2dev <path_to_cia> (--out <path_to_output_file>)")
    print("python3 ntool.py cci_dev2retail <path_to_cci> (--out <path_to_output_file>)")
    print("python3 ntool.py cci_retail2dev <path_to_cci> (--out <path_to_output_file>)")
    print("")
    print("Convert CCI to CIA")
    print("python3 ntool.py cci2cia <path_to_cci> (--out <path_to_output_file>) (--cci_dev) (--cia-dev)")
    print("")
    print("Convert CDN contents to CIA")
    print("python3 ntool.py cdn2cia <path_to_cdn_folder> (--out <path_to_output_file>) (--title-ver <ver>) (--cdn-dev) (--cia-dev)")
    print("")
    print("Convert CIA to CDN contents")
    print("python3 ntool.py cia2cdn <path_to_cia> (--out <path_to_output_folder>) (--titlekey <titlekey>) (--cia-dev)")
    print("")
    print("Full extraction and rebuild of NCCH/CIA/CCI:")
    print("python3 ntool.py ncch_extractall <path_to_ncch> (--dev)")
    print("python3 ntool.py ncch_rebuildall <path_to_folder> (--dev)")
    print("python3 ntool.py cia_extractall <path_to_cia> (--dev)")
    print("python3 ntool.py cia_rebuildall <path_to_folder> (--dev)")
    print("python3 ntool.py cci_extractall <path_to_cci> (--dev)")
    print("python3 ntool.py cci_rebuildall <path_to_folder> (--dev)")
