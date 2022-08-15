# Pent-art

<img src="https://img.shields.io/badge/bash-script-blue"> <img src="https://img.shields.io/badge/nmap-automator-brightgreen"> <img src="https://img.shields.io/badge/efficient-port%20scan-important">

This tool is basically a bash script for performing **host probing** & **vulnerability assessment** via powerful Nmap port scanner sequentially. All you need to do is to create a target list and pass it to the tool, it'll do the rest for you!

Pent-art is a tool with multiple outputs. Not only will It export all the Nmap scans as XML files, but also it'll create multiple Excel files called **_CompSys_** for its various stages to provide a better understanding of the scans' results. 

✔ What's more, at the end of its multiple TCP scan phases, it'll create a workspace in metasploit, called **_TCPWholeScan_** and then import all the XML outputs in it, so that everyone can conveniently access port scan results on their systems after the scan is almost done!
