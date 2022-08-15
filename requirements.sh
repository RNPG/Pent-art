#!/bin/bash

apt install git -y
apt install python3-pip -y

git clone https://github.com/CBHue/nMap_Merger.git
git clone https://github.com/mrschyte/nmap-converter.git

chmod +x ./nMap_Merger/nMapMerge.py
chmod +x ./nmap-converter/nmap-converter.py

pip3 install -r ./nmap-converter/requirements.txt
