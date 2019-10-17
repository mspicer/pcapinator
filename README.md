# pcapinator
An application to deal with lots of pcaps by running lots of tsharks

# Setup

Install Python3, the one true Python... 

```
pip install python-dateutil pandas
```

# Features

Recursively process multiple PCAP files including those in subdirectories.

Wrapper around editcap (Wireshark Tool) that will let the user break PCAP files into smaller pieces.

Automatically grab all handshakes save as a pcap and also hashcat file for processing.

Wrapper around tshark that will let the user filter pcap files for handshakes and output as pcap.

Gathers standard wireless info and puts it into a CSV

# USAGE Examples:

Run PCAPFix on the dataset to repair damaged or cutshort PCAPs. 

`./pcapinator.py --in [directory or file] --pcapfix --pcapfix_dir [directory for original pcaps before fix] --debug`

Gather all of the typical wireless information from a pcap and output a single CSV. This will split the PCAP files and procees them based on the number of CPU cores you have. 

`./pcapinator.py --in [directory or file] --wifi_csv --split --debug`

Run a custom tshark query and output the fields you specify. In this case its searching for anything email related and ouputting related interesting fields. 

`./pcapinator.py --in [directory or file] --query "tcp.port == 143 || tcp.port == 110 || tcp.port == 25 || tcp.port == 26 || pop || imap || smtp" --fields "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e text -e tcp.payload" --split --debug`

A custom query to get HTTP data.

`./pcapinator.py --in [directory or file] --query "http" --fields "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e text -e tcp.payload" --split --debug`

A custom query to get SSIDs that contain the letters TEST, change TEST to your partial search parameter.

./pcapinator.py --in /mnt/e/CapData/DC2018\ -\ WiFiCactus/ --query "wlan.ssid contains TEST" --fields "-e frame.time -e frame.time_epoch -e wlan.sa -e wlan.ta -e wlan.ta_resolved -e wlan.ra -e wlan.da -e wlan.bssid -e wlan.ssid -e wps.manufacturer -e wps.device_name -e wps.model_name -e wps.model_number -e wps.uuid_e -e wlan.fc.type_subtype -e frame.len -e wlan_radio.signal_dbm" --split --debug

Get a CSV file with DNS info.

`./pcapinator.py --in [directory or file] --dnsSimple --split --debug`

# Future Features 

Automatic import into Postgres database from a PCAP file.

Automatic import into Elastic Stack.

Automatic push into Graphistry

Generalized use around editcap to support other options supported by the tool.

Generalized use around tshark to support other options supported by the tool.

Tool to strip all unencrypted data from pcap files and put the results into new pcap files.

Tool to anonymize traffic datas but maintain context.