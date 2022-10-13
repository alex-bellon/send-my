cat $1 | awk '{ print "{0x" $0 "},"}' > formatted.txt
sed -i "s/ /, 0x/g" formatted.txt
