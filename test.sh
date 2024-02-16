./srtp-decrypt -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz -i marseillaise-srtp.pcap < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
