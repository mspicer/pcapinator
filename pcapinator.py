#!/usr/bin/env python3

import argparse
from dateutil import parser as dateparser
import datetime, time
import sqlite3
import sys
import csv
import multiprocessing as mp
import os, subprocess
import struct
from multiprocessing.pool import ThreadPool
from multiprocessing import Process
import pandas as pd
import shutil

VERBOSE = False
DEBUG = False
TIMED = False
TSHARK = ''
EDITCAP = ''
CAPINFOS = ''
MERGECAP = ''
WSHARK_DIR = ''
EXT = ''
CAP2HCCAPX = ''
PCAPFIXDIR = '' # This is where borked pcaps will go.
PCAPFIX = ''
MINSPLIT = 209715200

    

def main():
    global TSHARK, EDITCAP, CAPINFOS, MERGECAP, WSHARK_DIR, EXT, CAP2HCCAPX, VERBOSE, DEBUG, TIMED, PCAPFIX, PCAPFIXDIR, MINSPLIT

    parser = argparse.ArgumentParser(description="PCAPinator - Tool for crazy PCAP analysis")
    parser.add_argument("--in", action="store", dest="infile", help="Input PCAP file or directory", required=True)
    parser.add_argument("--kismetdb", action="store_true", dest="kismetdb", help="Extract PCAP files from Kismet DB")
    # parser.add_argument("-r", "--recursive", action="store_true", dest="recursive", help="Recursively search for PCAP files")
    parser.add_argument("--out", action="store", dest="outfile", help="Output file")
    # parser.add_argument("-h", "--help", action="store_true", dest="askhelp", help="Show the help")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Enable verbose mode")
    parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="Enable debugging output")
    parser.add_argument("--timed", action="store_true", dest="timed", help="Return the processing time of each portion of the code")
    parser.add_argument("--split", action="store_true", dest="split", help="Split the PCAP into pieces based on CPU count")
    parser.add_argument("--split_count", action="store", dest="split_count", help="Set the number of pieces the PCAP will be split into")
    parser.add_argument("--split_output", action="store", dest="split_output", help="Directory location of the newly split files")
    parser.add_argument("--wshark_dir", action="store", dest="wshark_dir", help="Define the location of the wireshark directory")
    parser.add_argument("--handshakes", action="store_true", dest="handshakes", help="Get WPA/WPA2 handshakes")
    parser.add_argument("--wifi_csv", action="store_true", dest="wifi_csv", help="Build CSV files with default tables")
    parser.add_argument("--hashcat", action="store_true", dest="hashcat", help="Output to Hashcat format")
    parser.add_argument("--dnsSimple", action="store_true", dest="dnssimple", help="Create a CSV of dns data only")
    parser.add_argument("--pcapfix", action="store_true", dest="pcapfix", help="Fixes Borked PCAP files, only works in *nix")
    parser.add_argument("--pcapfix_dir", action="store", dest="pcapfd", help="Set the PCAPFix directory where broken files will go")
    parser.add_argument("--min_split", action="store", dest="minsplitsz", help="Min Split Size in bytes, default 200 MB")
    parser.add_argument("--query", action="store", dest="tshark_query", help="A custom query that you want to run on a dataset, use with --fields")
    parser.add_argument("--fields", action="store", dest="tshark_fields", help="The fields list you would like to use with your query, use with --query")
    parser.add_argument("--unique_existing_tsv", action="store_true", dest="existing_tsv", help="Get unique data from an existing TSV file")
    parser.add_argument("--validate_wifi_tsv", action="store_true", dest="validate_tsv", help="Validate and fix a tsv file you are making")
    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True
    if args.debug:
        DEBUG = True
        TIMED = True
        print(args)
    if args.timed:
        TIMED = True
    
    if args.infile is None:
        usage(parser)
    # if args.askhelp:
    #     usage(parser)
    m_start_time = time.time()
    pcapfiles = []
    if DEBUG:
        print("args.infile: {}".format(args.infile))
    if os.path.isdir(args.infile) and args.existing_tsv:
        tsvfiles = []
        tsvfiles = getFilesToProcess(args.infile, filetype='tsv')
        if args.validate_tsv:
            #Validate the TSV files based on requiring 16 tabs and an even number of double quote characters.
            fixedtsvfiles = []
            for tsvfile in tsvfiles:
                fixedtsvfiles.append(checkWiFiTSV(tsvfile))
            makeUniqueExistingTSV(fixedtsvfiles)
        else:
            #Process TSV files for uniqueness assume they files are fine
            makeUniqueExistingTSV(tsvfiles)
    elif os.path.isfile(args.infile) and args.existing_tsv:
        tsvfiles = []
        tsvfiles.append(args.infile)
        #Process TSV file for uniquess now
        makeUniqueExistingTSV(tsvfiles)
    elif os.path.isdir(args.infile) and args.kismetdb:
        kismetfiles = []
        kismetfiles = getFilesToProcess(args.infile, filetype='kismet')
        processKismetLog(kismetfiles)
        #Process Kismet DB then PCAP files
        pcapfiles = getFilesToProcess(args.infile)

    elif os.path.isfile(args.infile) and args.kismetdb:
        #Process kismet db before appending pcap file
        kismetfiles = []
        kismetfiles.append(args.infile)
        processKismetLog(kismetfiles)
        pcapfiles.append(args.infile + '.pcap')
    elif os.path.isdir(args.infile):
        pcapfiles = getFilesToProcess(args.infile)
        
    elif os.path.isfile(args.infile):
        pcapfiles.append(args.infile)


    if args.wshark_dir is not None:
        WSHARK_DIR = args.wshark_dir

    if os.name == 'nt':
        if VERBOSE: 
            print("WINDOWS FOUND")
        WSHARK_DIR = "C:/Program Files/Wireshark"
        EXT = ".exe"
        TSHARK = WSHARK_DIR + '/' + 'tshark' + EXT
        EDITCAP = WSHARK_DIR  + '/' + 'editcap' + EXT
        CAPINFOS = WSHARK_DIR + '/' + 'capinfos' + EXT
        MERGECAP = WSHARK_DIR + '/' + 'mergecap' + EXT
        #PCAPFIX = WSHARK_DIR + '/' + 'pcapfix' + EXT # DOES NOT SUPPORT WINDOWS :(
        CAP2HCCAPX = os.path.abspath('hashcat-utils-1.9/bin/cap2hccapx.exe')
    else:
        if VERBOSE:
            print("NOT WINDOWS FOUND")
        WSHARK_DIR = "/usr/bin/"
        TSHARK = WSHARK_DIR + 'tshark' + EXT
        EDITCAP = WSHARK_DIR  + 'editcap' + EXT
        CAPINFOS = WSHARK_DIR + 'capinfos' + EXT
        MERGECAP = WSHARK_DIR + 'mergecap' + EXT
        PCAPFIX = WSHARK_DIR + 'pcapfix' + EXT
        CAP2HCCAPX = os.path.abspath('hashcat-utils-1.9/bin/cap2hccapx.bin')

    if args.pcapfd is not None:
        if DEBUG:
            print("args.pcapfd: %s" % (args.pcapfd))
        PCAPFIXDIR = args.pcapfd
    else:
        PCAPFIXDIR = '/mnt/d/CutShortPCAPS'
        if DEBUG:
            print("args.pcapfd: %s" % (PCAPFIXDIR))

    if args.pcapfix and os.name == 'nt':
        print("Windows is not supported for PCAPFIX, time to install WSL or use Linux.")
        sys.exit(0)
    elif args.pcapfix:
        processpcapfix(pcapfiles)

    if args.minsplitsz is not None:
        MINSPLIT = args.minsplitsz

    if args.split or args.split_count:
        split_count = 0
        split_output = ''
        if args.split_output is not None:
            split_output = args.split_output + '/'
            if not os.path.exists(args.split_output):
                os.mkdir(args.split_output)
        if args.split_count is not None:
            split_count = int(args.split_count)
        if len(pcapfiles)>0:
            for pcapf in pcapfiles:
                if DEBUG:
                    print("Splitting: {}".format(pcapf))
                splitpcap(pcapf, split_output, split_count)
        else:
            splitpcap(args.infile, split_output, split_count)
    
    if args.handshakes and (args.split or args.split_count):
        if args.split_output:
            pcapfiles = getFileSplitsToProcess(args.split_output)
            processHandshakes(pcapfiles, split_output)
        else:    
            pcapfiles = getFileSplitsToProcess('.')
            processHandshakes(pcapfiles, split_output)
        if args.hashcat:
            convert2hccapx()
    elif args.handshakes:
        processHandshakes(pcapfiles)
        if args.hashcat:
            convert2hccapx()
    elif args.hashcat:
        for pcapf in pcapfiles:
            convert2hccapx(pcapfile=pcapf)

    if args.wifi_csv and args.split:
        pcapdir = ''
        if args.split_output is not None:
            pcapdir = args.split_output
            pcapfiles = getFileSplitsToProcess(args.split_output)
            processCSV(pcapfiles, args.split_output)
        else:
            pcapfiles = getFileSplitsToProcess('.')
            processCSV(pcapfiles, '.')
    elif args.wifi_csv and args.split_output:
        processCSV(pcapfiles, args.split_output)
    elif args.wifi_csv:
        processCSV(pcapfiles, '.')
    
    if args.dnssimple and args.split:
        pcapdir = ''
        if args.split_output is not None:
            pcapdir = args.split_output
        pcapfiles = getFileSplitsToProcess('.')
        processDNSSimple(pcapfiles)
    elif args.dnssimple:
        processDNSSimple(pcapfiles)
    
    if args.tshark_query and args.tshark_fields and args.split:
        pcapdir = ''
        if args.split_output is not None:
            pcapdir = args.split_output
        pcapfiles = getFileSplitsToProcess('.')
        processCustomQuery(pcapfiles, args.tshark_query, args.tshark_fields, pcapdir)
    elif args.tshark_query and args.tshark_fields:
        processCustomQuery(pcapfiles, args.tshark_query, args.tshark_fields, '.')

    
    if TIMED:
        print("---- Ran pcapinator: {} Seconds ----".format(time.time()-m_start_time))

def convert2hccapx(**kwargs):
    output_hccapx = 'handshakes.hccapx'
    if len(kwargs) == 0:
        if os.path.isfile('handshakes.pcap'):
            i = 1
            while os.path.isfile(output_hccapx):
                output_hccapx = "handshakes.{}.hccapx".format(i)
                i = i +1
            start_time = time.time()
            if DEBUG:
                print('CMD# "{}" handshakes.pcap {}'.format(CAP2HCCAPX, output_hccapx))
            subprocess.call ('"{}" handshakes.pcap {}'.format(CAP2HCCAPX, output_hccapx), shell=True)
            if TIMED:
                print("---- Ran cap2hccapx: {} Seconds ----".format(time.time()-start_time))
    elif 'pcapfile' in kwargs:
        if os.path.isfile(kwargs.get('pcapfile')):
            start_time = time.time()
            if DEBUG:
                print('CMD# "{}" "{}" handshakes.hccapx'.format(CAP2HCCAPX, kwargs.get('pcapfile')))
            subprocess.call ('"""{}""" "{}" handshakes.hccapx'.format(CAP2HCCAPX, kwargs.get('pcapfile')), shell=True)
            if TIMED:
                print("---- Ran cap2hccapx: {} Seconds ----".format(time.time()-start_time))

    else:
        print("Did not find handshakes.pcap something went wrong, alert a programmer that they suck.")
        sys.exit(1)

def processHandshakes(pcapfiles, split_output):
    if len(pcapfiles) < mp.cpu_count():
        pool = ThreadPool(len(pcapfiles))
    else:
        pool = ThreadPool(mp.cpu_count())
    
    results = []
    pid = 0
    for f in pcapfiles:
        #-2 means that tshark will perform a two-pass analysis causing buffered output until the entire first pass is done. Prevents errors.
        filename_w_ext = os.path.basename(f)
        filename, file_extension = os.path.splitext(filename_w_ext)
        
        tshark_args = '-R "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05 || eapol)" -2 -F pcap -w hs_{}.pcap'.format(filename)
        #tsharking(inpcap, params, output, outext, procid)
        results.append(pool.apply_async(tsharking, (f, tshark_args, '', '', pid)))
        pid = pid+1

    pool.close()
    pool.join()
    mergePcaps()
    cleanHandshakes()
    cleanSplits(split_output)

def processCSV(pcapfiles, split_output):
    if len(pcapfiles) == 0:
        if DEBUG: 
            print("PCAPFILES is length 0 for some reason, something is broken exiting: {}".format(pcapfiles))
        return
    if len(pcapfiles) < mp.cpu_count():
        pool = ThreadPool(len(pcapfiles))
    else:
        pool = ThreadPool(mp.cpu_count())
    results = []
    pid = 0
    for f in pcapfiles:
        filename_w_ext = os.path.basename(f)
        filename, file_extension = os.path.splitext(filename_w_ext)
        tshark_args = '-T fields \
                            -e frame.time \
                            -e frame.time_epoch \
                            -e wlan.sa \
                            -e wlan.ta \
                            -e wlan.ta_resolved \
                            -e wlan.ra \
                            -e wlan.da \
                            -e wlan.bssid \
                            -e wlan.ssid \
                            -e wps.manufacturer \
                            -e wps.device_name \
                            -e wps.model_name \
                            -e wps.model_number \
                            -e wps.uuid_e \
                            -e wlan.fc.type_subtype \
                            -e frame.len \
                            -e wlan_radio.signal_dbm \
                            -E separator=/t -E quote=d -E occurrence=f'
        #tshark_args = tshark_args.replace('\n', '')
        tshark_args = tshark_args.replace('    ', '')
        tshark_outargs = filename
        tshark_outext = 'tsv'
        
        results.append(pool.apply_async(tsharking, (f, tshark_args, tshark_outargs, tshark_outext, pid, split_output)))
        pid = pid+1

    pool.close()
    pool.join()
    if len(pcapfiles)>1:
        mergeCSV(split_output)
        cleanSplits(split_output)

def processCustomQuery(pcapfiles, qry, fields, split_output):
    global TSHARK, EDITCAP, CAPINFOS, EXT, VERBOSE, DEBUG, TIMED, PCAPFIX
    if len(pcapfiles) < mp.cpu_count():
        pool = ThreadPool(len(pcapfiles))
    else:
        pool = ThreadPool(mp.cpu_count())
    results = []
    pid = 0
    for f in pcapfiles:
        filename_w_ext = os.path.basename(f)
        filename, file_extension = os.path.splitext(filename_w_ext)
        tshark_args = '-T fields \
                        {} \
                        -E separator=/t -E quote=d -E occurrence=f "{}"'.format(fields, qry)
        tshark_args = tshark_args.replace('    ', '')
        tshark_outargs = filename
        tshark_outext = 'tsv'
        results.append(pool.apply_async(tsharking, (f, tshark_args, tshark_outargs, tshark_outext, pid)))
        pid = pid+1

    pool.close()
    pool.join()
    if len(pcapfiles)>1:
        tsvfile = mergeCSV()
        cleanSplits(split_output)


def processDNSSimple(pcapfiles):
    global TSHARK, EDITCAP, CAPINFOS, EXT, VERBOSE, DEBUG, TIMED, PCAPFIX
    if len(pcapfiles) < mp.cpu_count():
        pool = ThreadPool(len(pcapfiles))
    else:
        pool = ThreadPool(mp.cpu_count())
    results = []
    pid = 0
    for f in pcapfiles:
        filename_w_ext = os.path.basename(f)
        filename, file_extension = os.path.splitext(filename_w_ext)
        tshark_args = '-T fields \
                        -e dns.qry.name -e dns.resp.name -e dns.a -e dns.aaaa -e dns.cname \
                        -e wlan.sa -e wlan.ta -e wlan.da -e wlan.ra -e dns.srv.proto \
                        -E separator=/t -E quote=d -E occurrence=f "dns || mdns"'
        #tshark_args = tshark_args.replace('\n', '')
        tshark_args = tshark_args.replace('    ', '')
        tshark_outargs = filename
        tshark_outext = 'tsv'
        
        results.append(pool.apply_async(tsharking, (f, tshark_args, tshark_outargs, tshark_outext, pid)))
        pid = pid+1

    pool.close()
    pool.join()
    if len(pcapfiles)>1:
        tsvfile = mergeCSV()
        cleanSplits()
        hasdup = pd.read_csv(tsvfile, sep='\t', lineterminator='\n', names=['qname', 'rname', 'A_rec', 'AAAA_rec', 'Cname', 'sa', 'ta', 'da', 'ra', 'srv_proto'])
        unique = hasdup.drop_duplicates(subset=['qname']).sort_values(by='qname')
        unique.to_csv('unique-'+tsvfile, sep='\t', index=False)

# TODO: Add the abillity to call this function from the command line, test for functionality

def checkWiFiTSV(tsvfile):
    start_time = time.time()
    global DEBUG, TIMED
    brokenlines = []
    #tsvfile = 'fixed-729-10-09-57-1-20180812150253.pcap.tsv'
    with open('fixed-{}'.format(tsvfile), 'w+') as nf:
        with open(tsvfile) as f:
            i = 0
            for line in f:
                quotecnt = line.count('"')
                tabcnt = line.count('\t')
                if (quotecnt%2 != 0) or tabcnt != 16:
                    if DEBUG:
                        print("Broken Line: {} (quotecnt: {}, tabcnt: {})".format(i, quotecnt, tabcnt))
                        print("** FULL LINE: {}".format(line))
                    if tabcnt == 16:
                        #try to fix it
                        nf.write(fixWiFiTSVSSID(line))
                        print("---- Ran fixWiFiTSVSSID on file {}: {} Seconds ----".format(tsvfile, time.time()-start_time))
                else:
                    nf.write(line)
                i = i + 1
    print("---- Finished checkWiFiTSV on File {} in: {} Seconds ----".format(tsvfile,time.time()-start_time))
    return 'fixed-{}'.format(tsvfile)

def findnth(haystack, needle, n):
    parts = haystack.split(needle, n)
    if len(parts)<=n:
        return -1
    return len(haystack)-len(parts[-1])-len(needle)

def fixWiFiTSVSSID(brokenstr):
    pos = 0

    stpos = findnth(brokenstr, '\t', 8)
    enpos = findnth(brokenstr, '\t', 9)

    brokessid = brokenstr[stpos+1:enpos]
    pos = 0
    newssid = ""
    pos = findnth(brokessid, '"', 2)
    newssid = brokessid[:pos] + brokessid[pos+1:]
    fixedline = brokenstr[:stpos+1] + newssid + brokenstr[enpos:]
    return fixedline


def makeUniqueExistingTSV(tsvfiles):
    global VERBOSE, DEBUG, TIMED
    start_time = time.time()
    MAXSIZE = 1024*1024*1024 #1GB
    CHUNKSZ = 100000000
    if DEBUG:
        print("Making unique on %d files" % len(tsvfiles))
    if len(tsvfiles) > 0:
        for tsvfile in tsvfiles:
            if os.stat(tsvfile).st_size < MAXSIZE:
                hasdup = pd.read_csv(tsvfile, sep='\t', lineterminator='\n', names=['time', 'time_epoch', 'sa', 'ta', 'ta_resolved', 'ra', 'da', 'bssid', 'ssid', 'manufacturer', 'device_name', 'model_name', 'model_number', 'uuid_e', 'fc_type_subtype', 'frame_len', 'signal'],dtype={'device_name': 'object', 'manufacturer': 'object', 'model_name': 'object', 'model_number': 'object','uuid_e':'object', 'fc_type_subtype': 'Int64' })
                if TIMED:
                    print("---- Read CSV in: {} Seconds ----".format(time.time()-start_time))
                unique = hasdup.drop_duplicates(subset=['ssid']).sort_values(by='ssid')
                unique.to_csv('unique-'+tsvfile, sep='\t', index=False)
            else:
                i=0
                for chunk in pd.read_csv(tsvfile, sep='\t', lineterminator='\n', names=['time', 'time_epoch', 'sa', 'ta', 'ta_resolved', 'ra', 'da', 'bssid', 'ssid', 'manufacturer', 'device_name', 'model_name', 'model_number', 'uuid_e', 'fc_type_subtype', 'frame_len', 'signal'], chunksize=CHUNKSZ, dtype={'device_name': 'object', 'manufacturer': 'object', 'model_name': 'object', 'model_number': 'object','uuid_e':'object', 'fc_type_subtype': 'Int64' }):
                    if TIMED:
                        print("---- Read in CSV Chunk {} in: {} Seconds ----".format(i,time.time()-start_time))
                    unique = chunk.drop_duplicates(subset=['ssid'])
                    print(tsvfile)
                    unique.to_csv("chunk_{}-{}.tsv".format(tsvfile[:-4],i),sep='\t', index=False)
                    if TIMED:
                        print("---- Unique'd CSV Chunk {} in: {} Seconds ----".format(i,time.time()-start_time))
                    i = i + 1
                #Merge chunks back together then unique them
                chunkdir = os.path.abspath(tsvfile)
                tsv_files = [os.path.abspath(fl) for fl in os.listdir(chunkdir) if 'chunk' in fl and fl.endswith('tsv')]
                out_filename = "init-merge-{}".format(tsvfile)
                with open(out_filename, 'wb') as fout:
                    for f in tsv_files:
                        with open(f, 'rb') as fin:
                            fin.readline()
                            fout.write(fin.read())
                for f in tsv_files:
                    os.remove(f)
                # Unique and sort one more time without chunking to make sure we have a unique datasaet.
                hasdup = pd.read_csv(tsvfile, sep='\t', lineterminator='\n', names=['time', 'time_epoch', 'sa', 'ta', 'ta_resolved', 'ra', 'da', 'bssid', 'ssid', 'manufacturer', 'device_name', 'model_name', 'model_number', 'uuid_e', 'fc_type_subtype', 'frame_len', 'signal'],dtype={'device_name': 'object', 'manufacturer': 'object', 'model_name': 'object', 'model_number': 'object','uuid_e':'object', 'fc_type_subtype': 'Int64' })
                unique = hasdup.drop_duplicates(subset=['ssid']).sort_values(by='ssid')
                unique.to_csv('unique-'+tsvfile, sep='\t', index=False)

                if TIMED:
                    print("---- Finished CSV Chunking in: {} Seconds ----".format(time.time()-start_time))
        
        if TIMED:
            print("---- Ran Unique-ing process in: {} Seconds ----".format(time.time()-start_time))
    else:
        print("Something went wrong, no files sent to makeUniqueExistingTSV")
    if TIMED:
        print("---- Finished full Unique process in: {} Seconds ----".format(time.time()-start_time))

# TODO: Build a dossier about a mac address
# What is interesting now about a mac address?
# What networks are they probing? What other sites are they visiting? 

# TODO: Process and return a list of everything encrypted and what encryption type 
# IE: wlan.rsn.akms.type == psk

# TODO: Get a list of all the SSID's and unique it

# TODO: Build summary endpoint and conversation reports for IP, TCP, UDP
# tshark -r input.cap.pcapng -q -z conv,ip > output.txt
# tshark -r input.cap.pcapng -q -z endpoint,ip > output.txt
# Gotta parse the output reports and send to Graphistry 


# TODO: Need to make mergeCSV handle the case where there are multiple pcaps but not split...
# I think the above is handled now because I copy a file over and prepend 'split' to it... need to double check.

def mergeCSV(outdir):
    global VERBOSE, DEBUG, TIMED
    OUT_PATH = os.path.abspath(outdir)
    if DEBUG:
        print('outdir: {}'.format(outdir))
        print('OUTPATH: {}'.format(OUT_PATH))
    tsv_files = [os.path.abspath(os.path.join(OUT_PATH,fl)) for fl in os.listdir(OUT_PATH) if 'split' in fl and fl.endswith('tsv')]
    
    # split_Kismet-20170726-10-21-17-1-fixed_00000_20170711010628.tsv
    # split_Kismet-20170725-09-35-21-1_00001_20170711010800.tsv
    # subprocess.call ('"{}" -F pcap -c {} "{}" {}split_{}.pcap'.format(EDITCAP, chunk_size, inpcap, outdir, filename), shell=True)
    #What's happening to them: -17-30-1-fixed-808-06-37-49-1.pcap.tsv

    if DEBUG:
        print("tsv_files: %s" %(tsv_files))
    # Check to see if it has a split time
    if 'split.tsv' not in tsv_files[0]:
        start_time = tsv_files[0].split('.')[0][-14:]
    else:
        start_time = tsv_files[1].split('.')[0][-14:]
    stop_time = tsv_files[-1].split('.')[0][-14:]
    out_filename = '{}-{}.pcap.tsv'.format(start_time, stop_time)
    with open(os.path.join(OUT_PATH,out_filename), 'wb') as fout:
        for f in tsv_files:
            if DEBUG:
                print("f: %s" % (f))            
            with open(f, 'rb') as fin:
                fin.readline()
                fout.write(fin.read())
    for f in tsv_files:
        os.remove(f)
    return out_filename

def mergePcaps():
    #mergecap -F pcap -w hs.pcap hs*.pcap
    if DEBUG:
        print('CMD# "{}" -F pcap -w handshakes.pcap hs*.pcap'.format(MERGECAP))
    start_time = time.time()
    subprocess.call ('"{}" -F pcap -w handshakes.pcap hs*.pcap'.format(MERGECAP), shell=True)
    if TIMED:
        print("---- Ran mergecap: {} Seconds ----".format(time.time()-start_time))

def cleanHandshakes(clean_dir='.'):
    global DEBUG
    if DEBUG:
        print('clean_dir: {}'.format(clean_dir))
    clean_dir = os.path.abspath(clean_dir)
    if DEBUG:
        print('clean_dir abspath: {}'.format(clean_dir))
    for f in os.listdir(clean_dir):
        if f.startswith('hs') and f.endswith('pcap') or f.endswith('pcapdump'):
            os.remove(os.path.join(clean_dir, f))

def cleanSplits(clean_dir):
    global DEBUG
    if DEBUG:
        print('clean_dir: {}'.format(clean_dir))
    clean_dir = os.path.abspath(clean_dir)
    for f in os.listdir(clean_dir):
        if f.startswith('split') and f.endswith('pcap') or f.endswith('pcapdump'):
            os.remove(os.path.join(clean_dir, f))

def processpcapfix(pcapfiles):
    global TSHARK, EDITCAP, CAPINFOS, EXT, VERBOSE, DEBUG, TIMED, PCAPFIX, PCAPFIXDIR
    if DEBUG:
        print("PCAPFIXDIR: %s" %(PCAPFIXDIR))
    if not os.path.exists(PCAPFIXDIR):
        os.mkdir(PCAPFIXDIR)
    for f in pcapfiles:
        fpath = os.path.dirname(os.path.abspath(f))
        filename_w_ext = os.path.basename(f)
        filename, file_extension = os.path.splitext(filename_w_ext)
        if DEBUG:
            print('\nfpath: %s  f: %s  filename_w_ext: %s  filename: %s  file_extension: %s\n' % (fpath,f, filename_w_ext, filename, file_extension))
            print('"{}" -o "{}-fixed{}" "{}"'.format(PCAPFIX, os.path.join(fpath, filename), file_extension, f))
        subprocess.call ('"{}" -o "{}-fixed{}" "{}"'.format(PCAPFIX, os.path.join(fpath, filename), file_extension, f), shell=True)
        if os.path.exists("{}-fixed{}".format(os.path.join(fpath, filename), file_extension)):
            if DEBUG:
                print('Moving a file that is bork\'d %s' %(f))
            os.rename(f, os.path.join(PCAPFIXDIR, filename_w_ext))
        
def splitpcap(inpcap, outdir, splitcnt):
    global TSHARK, EDITCAP, CAPINFOS, EXT, VERBOSE, DEBUG, TIMED, MINSPLIT

    if splitcnt == 0:
        splitcnt = mp.cpu_count()
    start_time = time.time()
    if DEBUG:
        print('CMD# "{}" -c -M -T -m "{}"'.format(CAPINFOS,inpcap))
    try:    
        packet_count = int(subprocess.check_output('"{}" -K -c -M -T -m "{}"'.format(CAPINFOS,inpcap), shell=True, encoding='utf8').split(',')[-1])
    except Exception as e:
        if DEBUG or VERBOSE:
            print('Error occured, run fixpcap first: %s' % (str(e.output)))
    if TIMED:
        print("---- Ran capinfos: {} Seconds ----".format(time.time()-start_time))
    chunk_size = int((packet_count / splitcnt) + 1)
    if VERBOSE:
        print('Packet Count: {}'.format(str(packet_count)))
        print('Chunk Size: {}'.format(chunk_size))

    start_time = time.time()
    filename_w_ext = os.path.basename(inpcap)
    filename, file_extension = os.path.splitext(filename_w_ext)
    filesz = os.stat(inpcap).st_size
    if filesz <= MINSPLIT:
        if DEBUG:
            print('*Copying, not splitting, too small*')
            print('CMD# cp {} {}split_{}'.format(inpcap, outdir, filename_w_ext))
        shutil.copyfile(inpcap, "{}split_{}".format(outdir, filename_w_ext))
        if TIMED:
            print("---- Ran shutil.copyfile: {} Seconds ----".format(time.time()-start_time))
    else:
        if DEBUG:
            print('CMD# "{}" -F pcap -c {} "{}" {}split_{}.pcap'.format(EDITCAP, chunk_size, inpcap, outdir, filename))
        subprocess.call ('"{}" -F pcap -c {} "{}" {}split_{}.pcap'.format(EDITCAP, chunk_size, inpcap, outdir, filename), shell=True)
        if TIMED:
            print("---- Ran editcap: {} Seconds ----".format(time.time()-start_time))

#Recursive by default I suppose
def getFilesToProcess(dir, **kwargs):
    global VERBOSE, DEBUG, TIMED
    if 'filetype' in kwargs:
        filetype = (kwargs.get('filetype'), kwargs.get('filetype'))
    else:
        filetype = ('pcap', 'pcapdump')
    files_to_parse = []
    for root, dirs, files in os.walk(dir):
        # if DEBUG:
        #     print("Listing files in: {}".format(dirs))
        for file in files:
            if file.endswith(filetype[0]) or file.endswith(filetype[1]):
                if DEBUG:
                    print(file)
                full_path = os.path.abspath(root + '/' + file)
                # event = os.path.basename(os.path.dirname(full_path)) # the current directory is here
                files_to_parse.append(full_path)
    if DEBUG:
        print("Found {} files to process".format(len(files_to_parse)))
    return files_to_parse

def getFileSplitsToProcess(dir):
    global VERBOSE, DEBUG, TIMED
    files_to_parse = []
    for root, dirs, files in os.walk(dir):
        # if DEBUG:
        #     print("Listing files in: {}".format(dirs))
        for file in files:
            if file.startswith('split') and (file.endswith('pcap') or file.endswith('pcapdump')):
                if DEBUG:
                    print(file)
                full_path = os.path.abspath(root + '/' + file)
                # event = os.path.basename(os.path.dirname(full_path)) # the current directory is here
                files_to_parse.append(full_path)
    if DEBUG:
        print("Found {} files to process".format(len(files_to_parse)))
    return files_to_parse

def tsharking(inpcap, params, output, outext, procid, outdir='.'):
    global TSHARK, EDITCAP, CAPINFOS, EXT, VERBOSE, DEBUG, TIMED
    
    start_time = time.time()
    if output == '' and outdir == '.':
        if DEBUG:
            print('{} -r "{}" {}'.format(TSHARK, inpcap, params))
        p = subprocess.Popen('"{}" -r "{}" {}'.format(TSHARK, inpcap, params), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    elif output == '':
        print('ERROR: Not sure why you are here, basically you called this function with an output directory but no output file.')
    else:
        outfullpath = ''
        # if outdir != '.':
        outfullpath = os.path.join(os.path.abspath(outdir), "{}.{}".format(output, outext))
        #OLD WAY, no dir support
        #if DEBUG:
        #     print('{} -r "{}" {} >> "{}{}.{}"'.format(TSHARK, inpcap, params, outpath, output, outext))
        # p = subprocess.Popen('"{}" -r "{}" {} >> "{}{}.{}"'.format(TSHARK, inpcap, params, outpath, output, outext), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        if DEBUG:
            print('{} -r "{}" {} >> "{}"'.format(TSHARK, inpcap, params, outfullpath))
        p = subprocess.Popen('"{}" -r "{}" {} >> "{}"'.format(TSHARK, inpcap, params, outfullpath), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    
    out, err = p.communicate()
    if TIMED:
        print("---- ProcID: {} Ran tshark: {} Seconds FILE: {} ----".format(procid, time.time()-start_time, inpcap))
    if DEBUG:
        if out:
            print("ProcID {} stdout: {}".format(procid, out))
        if err:
            print("ProcID {} stderr: {}".format(procid, err))
    return (out, err)

#### Stolen from kismet_log_to_pcap.py ####
# Write a raw pcap file header
def write_pcap_header(f, dlt):
    hdr = struct.pack('IHHiIII',
            0xa1b2c3d4, # magic
            2, 4, # version
            0, # offset
            0, # sigfigs
            8192, # max packet len
            dlt # packet type
            )

    f.write(hdr)

# Write a specific frame
def write_pcap_packet(f, timeval_s, timeval_us, packet_bytes):
    pkt = struct.pack('IIII',
            timeval_s,
            timeval_us,
            len(packet_bytes),
            len(packet_bytes)
            )
    f.write(pkt)
    f.write(packet_bytes)

#Adapted from kismet_log_to_pcap.py
def kismetLog2Pcap(kismetdb, pid):
    global VERBOSE, DEBUG, TIMED

    try:
        db = sqlite3.connect(kismetdb)
    except Exception as e:
        print("Failed to open kismet logfile: ", e)
        sys.exit(1)
    if DEBUG:
        print("Id: {} sqlite3 DB opened: {}".format(pid, kismetdb))
    sql = "SELECT ts_sec, ts_usec, dlt, datasource, packet FROM packets WHERE dlt > 0"
    outfile = kismetdb + '.pcap'
    logf = None
    lognum = 0

    c = db.cursor()
    
    npackets = 0
    for row in c.execute(sql):
        if logf == None:
            if DEBUG or VERBOSE:
                print("Id: {} Assuming dlt {} for all packets".format(pid, row[2]))
            
            if DEBUG or VERBOSE:
                print("Logging to {}".format(outfile))
            logf = open(outfile, 'wb')
            
            write_pcap_header(logf, row[2])
            
        write_pcap_packet(logf, row[0], row[1], row[4])
        npackets = npackets + 1

        
        if VERBOSE:
            if npackets % 1000 == 0:
                print("Id: {} Converted {} packets...".format(pid, npackets))

    if DEBUG or VERBOSE:
        print("Id: {} Done! Converted {} packets.".format(pid,npackets))

def processKismetLog(kismetdbs):
    global VERBOSE, DEBUG, TIMED
    
    if len(kismetdbs) < mp.cpu_count():
        pool = ThreadPool(len(kismetdbs))
    else:
        pool = ThreadPool(mp.cpu_count())

    results = []
    pid = 0
    for f in kismetdbs:
        #tsharking(inpcap, params, output, outext, procid)
        if DEBUG or VERBOSE:
            print("ID: {} Processing: {}".format(pid, f))
        results.append(pool.apply_async(kismetLog2Pcap, (f, pid)))
        pid = pid+1

    pool.close()
    pool.join()

def usage(parser):
    print("""-------------------------------------------------------------
                                                               
                    PCAPinator
                    
-------------------------------------------------------------
""")
    parser.print_help()
    sys.exit(1)

if __name__ == "__main__":
    main()