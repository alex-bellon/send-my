screen /dev/ttyUSB0 115200 -L

tail -f ~/logs/send-my.log | awk '{ print systime(), $0; fflush(); }' | tee ~/logs/send-my-timestamped.log
