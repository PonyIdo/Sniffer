savedcmd_/home/ido/Desktop/sniffer/sniffer.mod := printf '%s\n'   sniffer.o | awk '!x[$$0]++ { print("/home/ido/Desktop/sniffer/"$$0) }' > /home/ido/Desktop/sniffer/sniffer.mod
