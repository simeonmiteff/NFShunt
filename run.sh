#!/usr/bin/env sh
sudo ./pox.py nfshunt log --format="[%(asctime)s] %(module)s %(levelname)s %(message)s" log.level
