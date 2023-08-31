# Pent-art

<img src="https://img.shields.io/badge/bash-script-blue"> <img src="https://img.shields.io/badge/nmap-automator-brightgreen"> <img src="https://img.shields.io/badge/efficient-port%20scan-important">

This tool is basically a bash script for performing **host probing** & **vulnerability assessment** via powerful Nmap port scanner sequentially. All you need to do is to create a target list and pass it to the tool, it'll do the rest for you!

Pent-art is a tool with multiple outputs. Not only will it export all the Nmap scans as XML files, but also it'll create multiple Excel files called **_CompSys_** for its various stages to provide a better understanding of the scans' results. 

✔ What's more, at the end of its multiple TCP scan phases, it'll create a workspace in metasploit, called **_TCPWholeScan_** and then import all the XML outputs in it, so that everyone can conveniently access port scan results on their systems after the scan is almost done!

⚠ **Disclaimer: This tool is developed for educational purposes only.**


## Technical Analysis

When it comes to carry out an accurate host probing task, it's advised to divide it into multiple steps. To be more precise, we need to do the following steps:

1. Discover live hosts in a network
2. Perform a TCP/UDP scan on a number of top ports at first
3. Perform a TCP/UDP scan on all the port numbers 
4. Do a service and OS fingerprinting on only the detected open ports from the previous steps

Having said that, this tool follows the exact same steps. It'll first find out the live hosts of a given range, or if it's a single target, it'll make sure the host is up, and then does a TOP and FULL TCP scans on the targets. And since UDP scans are time-consuming, it'll perform UDP scans as its final steps. 

In addition to just perform a port scan, this tool also scans the targets with Nmap's VULN script so that we will know what possible vulnerabilities exist for our targets. Also, to make it even more convenient for users, we have included two output styles for this tool which are XML files of Nmap scans that later will be imported in a metasploit's workspace, and some Excel files of the scan's results. 

**NOTE: for the sake of being undetected by FW/IDPS, we have used SYN scan for our TCP phases.**

## How to install

### Requirements

Inorder to run this tool without any problems, you must have two Github projects in the same directory as this tool's. To do so, you can mauanlly download the following Github packages on your system:

* https://github.com/CBHue/nMap_Merger
* https://github.com/mrschyte/nmap-converter

Or simply you can use the bash script **requirements.sh**
```
chmod +x requirements.sh
./requirements.sh
```

### Usage

Now that you have the requirements, you can run the script as follows:
```
chmod +x nmap_automator.sh
./nmap_automator.sh -L <Path to your targets file>
```
Tool's options are demonstrated in the following image 

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/Options.PNG">

## Tool's Features

There are multiple functions defined in the tool's bash script, which carry out different tasks. Here is a list of them that can be commented if there is no need for them. 

* LiveHost --> it checks whether the target(s) is up **_[MANDATORY]_**
* TCPTop --> Performs a TCP SYN top scan
* TCPFull --> Perform a TCP SYN full scan [65535 ports]
* SOfingerprint --> Performs services and OS fingerprinting
* TCPVuln --> Runs the nmap's vuln script on open TCP ports it has found on targets
* MSF --> Imports all the TCP scan results (XML files) in a metasploit's workspace called **_TCPWholeScan_**
* UDPTop --> Performs a UDP top port scan
* UDPFull --> Performs a UDP full scan [65535 ports]
* UDPVuln --> Runs the Nmap's vuln script on all the open UDP ports which were found open

## Examples

#### TCP scans [top & full] examples

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/TCPScan_output.PNG">

#### TCP ports services & OS probing

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/SO_fingerprintoutput.PNG">

#### TCP vuln assessment with Nmap vuln script

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/TCPVuln_output.PNG">

#### UDP scans [top& full] examples

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/UDPScan_output.png">

#### Metasploit workspace

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/MSF_Workspace_output.PNG">

* the created workspace:

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/TCPWhole_workspace.PNG">

#### CompSys files

* Data of discovered ports and details about their services

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/CompSys_ServiceInfo.PNG">

* Data of the performed TCP vuln assessment

<img src="https://raw.githubusercontent.com/RNPG/Pent-art/main/CompSys_VulnScan.PNG">


## To do

1. We must add a closed port to the SOfingerprint phase for an accurate OS guessing by Nmap
2. Due to the former XML results being stored on our systems from previous scans, the final CompSys files contain all the previous results, it's better to create these files for each targets which are currently being scanned, not the whole previous targets. 
