# echo "Regular benchmark"
#.\artifacts\bin\x64_Release\test\xdpbench.exe tx -i 107 -p 4321 -t -q -id 0 -reqpps 335000 -reqbatch 16 -reqsamples 100000000 -u 524288 -b 16 -txio 1400 -tx_pattern $(.\artifacts\bin\x64_Release\test\pktcmd.exe udp 7C-1E-52-23-2A-87 12-34-56-78-9a-bc 10.12.6.2 20.168.56.237 1234 4321 1024) -s

# echo "Using pktcmd output, which is not necessary. Now all the output are treated as the pure content by xdpsrv"
#.\artifacts\bin\x64_Release\test\xdpsrv.exe tx -srcip 10.12.6.2 -p 1234 -t -q -id 0 -u 524288  -reqpps 0 -b 16 -txio 1024 -dst 20.168.56.237:4321 -tx_payload $(.\artifacts\bin\x64_Release\test\pktcmd.exe udp 7C-1E-52-23-2A-87 12-34-56-78-9a-bc 10.12.6.2 20.168.56.237 1234 4321 512) -s

# Important: User should use -payloadsize OR -tx_payload
# echo "Inject payload with Hex String"
#.\artifacts\bin\x64_Release\test\xdpsrv.exe tx -srcip 10.12.6.2 -p 1234 -t -q -id 0 -u 524288  -reqpps 0 -b 16 -txio 64 -dst 20.168.56.237:4321 -tx_payload 123456789abc123456789abc123456789abc123456789abc123456789abc1234 -s
# echo "Inject payloadsize only"
.\artifacts\bin\x64_Release\test\xdpsrv.exe tx -srcip 10.12.6.2 -p 1234 -t -q -id 0 -u 524288  -reqpps 0 -b 16 -txio 1024 -dst 20.168.56.237:4321 -payloadsize 32 -s