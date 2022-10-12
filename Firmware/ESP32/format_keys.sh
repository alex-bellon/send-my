cat keys-raw.txt | awk '{ print "    {0x" $0 "},"}' > keys-formatted.txt
