#!/bin/bash

####################################################################
#	this is a tool with the purpose of automating host probing #
#	with nmap, in 2 stages, "info gathering and host scan"     #
#	& "Vulnerability assessment with nmap's vulners script"    #
####################################################################

RED='\033[38;5;196m'
YELLOW='\033[0;33m'
GREEN='\e[38;5;47m'
NC='\033[0m'
BOLD='\e[1m'
BBlue='\e[44m'
PINK='\e[38;5;198m'
DIM='\e[2m'
BLINK='\e[5m'
UL='\e[4m'
BPINK='\e[48;5;197m'
BDarkBlue='\e[48;5;99m'
BRed='\e[48;5;125m'
BOrange='\e[48;5;208m'
BPurple='\e[48;5;128m'
BGreen='\e[48;5;28m'
BP='\e[48;5;201m'
BP2='\e[48;5;55m'

clear
echo -e "------------------------------------------------------------------------------------"
echo -e "|  			  Welcome to Nmap's Automator Script  			    |"
echo -e "|   	    			${BBlue}${BOLD}Version 6.0${NC} Feb 2021                                |"
echo -e "|									 	    |"
echo -e "|    ${BOLD}${PINK}NOTE:${NC} Keep in mind that at the end of each phase, you can access its output    |"
echo -e "|    ${BOLD}${PINK}NOTE:${NC} To check the progress of each phase, hit enter			    |"
echo "------------------------------------------------------------------------------------"
echo ""
echo ""

# Usage
usage(){
echo -e "${DIM}You just have to pass this tool, a list of your targets & it will do the rest for you!"
echo -e "CAUTION: the output of this tool, which are XML Nmap files and CompSys Excel file, will be saved in their corresponding folders.${NC}\n"
echo -e "${YELLOW} usage: ./nmap_automator.sh -L <Targets List> [OPTIONS: --tcp-top <num> --tcp-custom '<custom command>' -T <1-5> ...]${NC}\n"

echo -e "Parameters:"
echo -e "----------------------"
echo -e "-L			List of your targets (a text file with IP addresses or CIDR representation of targets, one per line)"
echo -e "--tcp-top		<OPTIONAL> Define the number of top ports you want to perform a TCP SYN scan with it [Default: 200]"
echo -e "			(Ex: --tcp-port 200)"
echo -e "--udp-top		<OPTIONAL> Define the number of top ports you want to perform a UDP scan with it [Default: 200]"
echo -e "			(Ex: --udp-port 200)"
echo -e "--tcp-scan-custom	<OPTIONAL> Define custom payloads for TCP SYN scan with --tcp-scan-custom"
echo -e "			[Default command: nmap -sS -p <ports> --reason -T <1-5> --open <IP> -oX <XML output>]"
echo -e "--udp-scan-custom	<OPTIONAL> Define custom payloads for UDP scan with --udp-scan-custom"
echo -e "			[Default command: nmap -sU -p <ports> -sV --version-all --reason -T <1-5> <IP> -oX <XML output> ]"
echo -e "			(Ex: --udp-scan-custom '--scan-delay 2s --disable-arp-ping')"
echo -e "--tcp-service-custom	<OPTIONAL> Define custom payloads for service/OS finerprint with --tcp-service-custom"
echo -e "			[Default command: nmap -sS -p <ports> -sV --version-all -O --osscan-guess --reason -T <1-5> -oX <XML output>]"
echo -e "			(Ex: --tcp-service-custom '--scan-delay 2s --disable-arp-ping')"
echo -e "-T/--thread		<OPTIONAL> Define the thread. [Default: T3]" 
echo -e "-h/--help		Show this help message and exit"
echo -e "\n"
echo -e "Examples:"
echo -e "----------------------"
echo -e "./nmap_automator.sh --tcp-top 300 -T 5 -L /root/targets.txt"
echo -e "./nmap_automator.sh -L /root/targets.txt --tcp-service-custom '--scan-delay 2s' --udp-top 100"
}

#-----------------------------
#	INPUT PARAMETERS
#-----------------------------
args=("$@")

#DEFAULT VALUES
tcp_top=200
tcp_scan_custom=""
tcp_service_custom=""
udp_top=200
udp_custom=""
thread=3

#check for params
for ((i=0; i < $#; i++))
{
	case ${args[$i]} in
	--tcp-top)
	#TCP TOP
	tcp_top=${args[$((i+1))]}
	;;
	--tcp-scan-custom)
	#TCP Custom Payload
	tcp_scan_custom=${args[$((i+1))]}
	;;
	--udp-scan-custom)
	#UDP Custom Payload
	udp_scan_custom=${args[$((i+1))]}
	;;
	--thread | -T)
	#thread
	thread=${args[$((i+1))]}
	;;
	--tcp-service-custom)
	#TCP service custom payload
	tcp_service_custom=${args[$((i+1))]}
	;;
	--udp-top)
	#UDP TOP
	udp_top=${args[$((i+1))]}
	;;
	-L)
	#Mandatory file path
	target_file=${args[$((i+1))]}
	;;
	-h | --help | "")
	#Help Menu
	usage
	exit 0
	;;
	esac
}


## checking the mandatory parameter (file name)
if [ -z "$target_file" ]  
then 
    usage
    echo ""
    echo -e "${RED}${BOLD} The ${UL}file parameter (-L) \e[24mis mandatory, please try again and provide your target list ${NC}"
    exit 0 
fi

# create an array of targets in the input file
target_array=()
while IFS= read -r line; do
	target_array+=("$line")
done < $target_file



#-------------------------
#	FUNCTIONS
#-------------------------

# ~~~~~~~~~ Live host scan ~~~~~~~~~~~
LiveHost(){

echo -e "${BPINK}${BOLD}           Live Hosts Scan             ${NC}"
# we need a counter for different IP ranges / IPs to create their corresponding output
f=0
# if the script has ran once, we have to empty the IPs.txt file before running again
echo "" > ./LiveHosts/IPs.txt

for y in ${target_array[@]}; do
	echo -e "${GREEN}[+] $y${NC}"
	nmap -sn $y -oG - | awk '/Up/ {print}' > /tmp/live_$f.txt
	cat /tmp/live_$f.txt
	echo ""
	#outputs_creation
	cat /tmp/live_$f.txt | awk '{print $2}' >> ./LiveHosts/IPs.txt
	f=$((f+1))	
done
sed -i '1d' ./LiveHosts/IPs.txt

# delete those files which were created in /tmp folder
rm -rf /tmp/live_*

# Error Handling: If there is no live host, the script should stop running
live_hosts=$( cat ./LiveHosts/IPs.txt )

if [ -z "$live_hosts" ]
then
	echo -e "${RED}No live host has been detected, the script is stopping now! ${NC}"
	exit
fi
}

# ~~~~~~~~~ TCP Top Ports SYN Scan ~~~~~~~~~~~
TCPTop(){
echo -e "${BDarkBlue}${BOLD}           TCP Top Ports SYN SCAN            ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	nmap -sS --top-ports $tcp_top -T $thread --reason --open $tcp_scan_custom  $line -oX ./TCPTop/$line.xml |tee /tmp/TCP_top_$line.txt | awk '/open/ && !/Discovered/ || /PORT/ || /%/'
	echo -e "\n"
	#outputs_creation
	cat /tmp/TCP_top_$line.txt | awk '/open/ && !/Discovered/' | cut -d '/' -f1 -  | tr '\n' ',' > ./TCPTop/OpenPorts/$line.txt
	
done < $IPs_file

# delete those files which were created in /tmp folder
rm -rf /tmp/TCP_top*
}

# ~~~~~~~~~ TCP FULL Ports SYN Scan ~~~~~~~~~~~
TCPFull(){
echo -e "${BRed}${BOLD}           TCP Full Ports SYN SCAN            ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	nmap -sS -p- --reason -T $thread $tcp_scan_custom --open $line -oX ./TCPFull/$line.xml |tee /tmp/TCP_full_$line.txt | awk '/open/ && !/Discovered/ || /PORT/ || /%/'
	echo -e "\n"	
	#outputs_creation
	cat /tmp/TCP_full_$line.txt | awk '/open/ && !/Discovered/' | cut -d '/' -f1 - | tr '\n' ',' > ./TCPFull/OpenPorts/$line.txt
		
done < $IPs_file

# delete those files which were created in /tmp folder
rm -rf /tmp/TCP_full*
}

# ~~~~~~~~~ Service & OS Fingerprint ~~~~~~~~~~~
SOfingerprint(){
echo -e "${BOrange}${BOLD}           (TCP) Service and OS Fingerprint            ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	ports=$( cat "./TCPFull/OpenPorts/$line.txt")
	# Error Handling (Check whether there is any open port discovered to perform OS/Service fingerprint or not)
	if [ -z "$ports" ]
	then
		echo -e "${RED} There is no open TCP port discovered for IP:${NC} $line ${RED}to perform an OS/Service fingerprint scan ${NC}"
	else
		nmap -sS -p $ports -sV --version-all -O --osscan-guess --reason -T $thread $tcp_service_custom $line -oX ./TCPServices/$line.xml |tee /tmp/TCPService_$line.txt | awk '/%/ && !/OS/'
		echo -e "${PINK}Service Fingerprint Result${NC}"	
		cat /tmp/TCPService_$line.txt | awk '/PORT/ || /open/ && !/Discovered/' 
		echo -e "\n"
		echo -e "${PINK}OS Fingerprint Result${NC}"
		cat /tmp/TCPService_$line.txt | grep "OS details"
		echo -e "\n"
	fi

done < $IPs_file

rm -rf /tmp/TCP_Services*

# Creating first version of CompSys
#1st step is to merge all service scans' XML files
python3 ./nMap_Merger/nMapMerge.py -q -d ./TCPServices/ 2> /dev/null

#now we can convert the merged XML file into a single excel file
python3 ./nmap-converter/nmap-converter.py ./nMap_Merged*.xml -o ./CompSys/CompSys_ServiceInfo.xlsx 2> /dev/null 

#rm -rf /tmp/log.txt
rm -rf ./nMap_Merged_*
echo -e "\n"
}


# ~~~~~~~~~ TCP Vuln Scan ~~~~~~~~~~~
TCPVuln(){
echo -e "${BPurple}${BOLD}           TCP Ports/Services Vulnerability Scan           ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	ports=$( cat "./TCPFull/OpenPorts/$line.txt")
	# Error Handling (Check whether there is any open port discovered to perform vulneraility scan or not)
	if [ -z "$ports" ]
	then
		echo -e "${RED} There is no open TCP port discovered for IP: ${NC}$line ${RED}to perform a vuln scan ${NC}"
	else
		nmap -sS -p $ports --script vuln --reason -T $thread $line -oX ./Vulns/TCP_Vulns_$line.xml | awk '/\|/ || /%/'
	fi

done < $IPs_file

# Creating 2nd version of CompSys
#1st step is to merge all service scans' XML files
python3 ./nMap_Merger/nMapMerge.py -q -d ./Vulns/

#now we can convert the merged XML file into a single excel file
python3 ./nmap-converter/nmap-converter.py ./nMap_Merged*.xml -o ./CompSys/CompSys_VulnScan.xlsx > /tmp/log.txt
rm -rf /tmp/log.txt
rm -rf ./nMap_Merged_*
}


# ~~~~~~~~~ UDP Top Scan & Service Fingerprint ~~~~~~~~~~~
UDPTop(){
echo -e "${BGreen}${BOLD}           UDP Top Scan & Service Fingerprint (It'll take a while)           ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	nmap -sU $line --top-ports $udp_top -T $thread $udp_scan_custom -sV --version-all --reason --open -oX ./UDPTop_Services/UDP_top_service_$line.xml | tee /tmp/UDPTop_$line.txt | awk '/open/ && !/Discovered/ || /PORT/ || /%/'
	echo -e "\n"
	#outputs_creation
	cat /tmp/UDPTop_$line.txt | awk '/open/ && !/Discovered/' | cut -d '/' -f1 - | tr '\n' ',' > ./UDPTop_Services/OpenPorts/$line.txt

done < $IPs_file
rm -rf /tmp/UDPTop_*.txt


}

# ~~~~~~~~~ UDP Full Scan & Service discovery ~~~~~~~~~~~
UDPFull(){
echo -e "${BP}${BOLD}           UDP Full Scan & Service Fingerprint (It'll take a while)           ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	nmap -sU $line -p- -sV --version-all --reason $udp_scan_custom -T $thread --open -oX ./UDPFull_Services/UDP_full_service_$line.xml | tee /tmp/UDPFull_$line.txt | awk '/open/ && !/Discovered/ || /PORT/ || /%/'
	echo -e "\n"
	#outputs_creation
	cat /tmp/UDPFull_$line.txt | awk '/open/ && !/Discovered/' | cut -d '/' -f1 - | tr '\n' ',' > ./UDPFull_Services/OpenPorts/$line.txt

done < $IPs_file
rm -rf /tmp/UDPFull_*.txt
}

# ~~~~~~~~~ UDP Vuln Scan ~~~~~~~~~~~
UDPVuln(){
echo -e "${BP2}${BOLD}           UDP Ports/Services Vulnerability Scan (It'll take a while)          ${NC}"

while IFS= read -r  line; do
	echo -e "${GREEN}[+] $line${NC}"
	ports=$( cat "./UDPFull_Services/OpenPorts/$line.txt")

	# Error Handling (Check whether there is any open port discovered to perform vulneraility scan or not)
	if [ -z "$ports" ]
	then
		echo -e "${RED} There is no open UDP port discovered for IP: ${NC}$line ${RED}to perform a vuln scan ${NC}"
	else
		nmap -sU -p $ports --script vuln --reason -T $thread $line -oX ./Vulns/UDP_Vulns_$line.xml | awk '/\|/ || /%/'
	fi

done < $IPs_file

# Creating 3rd version of CompSys
#1st step is to merge all service scans' XML files
python3 ./nMap_Merger/nMapMerge.py -q -d ./Vulns/

#now we can convert the merged XML file into a single excel file
python3 ./nmap-converter/nmap-converter.py ./nMap_Merged*.xml -o ./CompSys/CompSys_VulnScan_UDP_Included.xlsx > /tmp/log.txt
rm -rf /tmp/log.txt
rm -rf ./nMap_Merged_*



} 

# ~~~~~~~~~ Creating Metasploit's Workspace for Our Scan~~~~~~~~~~~
MSF(){
echo -e "${BPINK}${BOLD}          Creating Metasploit Workspace for TCP Scans         ${NC}"
msfdb init
msfconsole -r ./MSF/Workspace.rc
echo -e "\n"
} 


#-------------------------
#	MAIN PART
#-------------------------

# print user's input
echo "+------------------------------+"
echo -e "${BOLD}   Your Targets:"
index=1
for x in ${target_array[@]}; do
	echo -e "   [$index] $x"
	index=$((index+1))
done
echo -e "${NC}+------------------------------+"
echo ""

# perform the host scan
LiveHost
IPs_file='./LiveHosts/IPs.txt'

# perform the TCP top ports scan
TCPTop

# perform the TCP full ports scan
TCPFull

# perform service & OS fingerprinting
SOfingerprint

# perform TCP vuln scan
TCPVuln

# Metasploit workspace creation
MSF

# perform UDP Top scan & Service fingerprint
UDPTop

# perform UDP Full scan & Service fingerprint
UDPFull

# perform UDP Vuln scan
UDPVuln

