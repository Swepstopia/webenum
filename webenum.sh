#!/bin/bash

#Setup directories
function setup-directories {
        output_parent_dir="$(pwd)"  #Change this to the desired parent directory
	current_date=$(date +%Y-%m-%d_%H-%M-%S)
	output_dir="$output_parent_dir/$current_date/$target_domain"
	subdomain_dir="$output_dir/subdomain_enum"
	tools_dir="$output_dir/tools"
	portscans_dir="$output_dir/port-scans"
	reports_dir="$output_dir/reports"
	aquatone_report_dir="$reports_dir/aquatone_report"
	webports_report_dir="$reports_dir/webports_report"
	nuclei_report_dir="$reports_dir/nuclei_report"
	
	mkdir -p $output_dir
	mkdir -p $subdomain_dir
	mkdir -p $tools_dir
	mkdir -p $portscans_dir
	mkdir -p $reports_dir
	mkdir -p $nuclei_report_dir	
}

#Install the required tools
function preflight_dependency_check {
	echo -e '\n\n########################################################################################################\n######################## INSTALLING REQUIREMENTS AND DEPENDENCIES ######################################\n########################################################################################################\n\n'

	apt update -y
	apt-get install chromium -y
	apt install subfinder -y
	apt install parallel -y
	apt install gobuster -y
	apt install xsltproc -y 
	go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	ln -s /home/$(whoami)/go/bin/nuclei /usr/local/bin/nuclei
	nuclei --update
	nuclei -ut
	apt install nmap -y
	apt install seclists -y
	pip install elementpath
	
	#Check if rustscan is already installed and install if its not
	if [ ! -f /usr/bin/rustscan ]; then
		curl https://sh.rustup.rs -sSf | sh
	fi
	#update file database
	echo -e "\nUpdating file database. This will take a few seconds...\n"
	updatedb	
}

#Create subdomain list using subfinder
function perform_subfinder_enumeration {
	echo -e '\n\n########################################################################################################\n######################## SUDOMAIN ENUMERATION WITH SUBFINDER ###########################################\n########################################################################################################\n\n'
	subfinder -d $target_domain -o $subdomain_dir/temp.txt
	cat $subdomain_dir/temp.txt | sort -u >> $subdomain_dir/subdomains.txt
	rm $subdomain_dir/temp.txt
}

#Create subdomain list using Gobuster
function perform_gobuster_enumeration {
	gobuster -t $threads -r 8.8.8.8 -v dns -w $(locate dns-Jhaddix.txt) -d $target_domain -o $subdomain_dir/temp.txt
	cat $subdomain_dir/temp.txt | sort -u >> $subdomain_dir/subdomains.txt
	rm $subdomain_dir/temp.txt
}

#Create subdomain list using CRT.SH
function perform_crtsh_subdomain_enumeration {
echo -e '\n\n########################################################################################################\n######################## SUDOMAIN ENUMERATION WITH CRT.SH ##############################################\n########################################################################################################\n\n'
	curl -s https://crt.sh/\?q\=$target_domain\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u >> $subdomain_dir/temp.txt
	cat $subdomain_dir/temp.txt
	cat $subdomain_dir/temp.txt | sort -u >> $subdomain_dir/subdomains.txt
	rm $subdomain_dir/temp.txt
	
	echo -e "\n\n$(wc -l < $subdomain_dir/subdomains.txt) unique subdomains\n\n"
}

#Remove duplicate domain names 
function remove_duplicate_subdomains {
echo -e '\n\n########################################################################################################\n######################## REMOVING DUPLICATE ENTRIES ####################################################\n########################################################################################################\n\n'
	cat $subdomain_dir/subdomains.txt | sort -u >> $subdomain_dir/temp.txt
	rm $subdomain_dir/subdomains.txt
	cat $subdomain_dir/temp.txt | sort -u >>  $subdomain_dir/subdomains.txt
	rm $subdomain_dir/temp.txt	
	echo -e "$(wc -l < $subdomain_dir/subdomains.txt) unique subdomains\n\n"
}

function perform_aquatone {
	echo -e '\n\n########################################################################################################\n######################## SCREENSHOTTING WITH AQUATONE ##################################################\n########################################################################################################\n\n'
	if [[ ! -f $tools_dir/aquatone_linux_amd64_1.7.0.zip || ! -f $tools_dir/aquatone ]]; then
		wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O $tools_dir/aquatone_linux_amd64_1.7.0.zip
		unzip -o "$tools_dir/aquatone_linux_amd64_1.7.0.zip" -d "$tools_dir"
	fi
	
	cat $portscans_dir/web-ports.xml | $tools_dir/aquatone -nmap -out $aquatone_report_dir	
}

function filter_live_hosts {
echo -e '\n\n########################################################################################################\n######################## FILTERING COMPANY SERVERS #####################################################\n########################################################################################################\n\nThis may take a few minutes...\n\n'
	for i in $(cat $subdomain_dir/subdomains.txt);do host $i | grep "has address" | cut -d " " -f 1 >> $subdomain_dir/temp.txt;done
	rm $subdomain_dir/subdomains.txt
	cat $subdomain_dir/temp.txt | sort -u >> $subdomain_dir/subdomains.txt
	rm $subdomain_dir/temp.txt
	echo -e "$(wc -l < $subdomain_dir/subdomains.txt) unique subdomains\n\n"
}

function generate_html_portscan_report {
	
	echo -e '\n\n########################################################################################################\n######################## GENERATING HTML REPORT FROM PORTSCAN ##########################################\n########################################################################################################\n\n'
	xsltproc $portscans_dir/web-ports.xml -o $webports_report_dir/web-ports.html

}

function perform_nuclei_scan {
	echo -e '\n\n########################################################################################################\n######################## VULNERABILITY SCANNING WITH NUCLEI ############################################\n########################################################################################################\n\n'
	create_python_parsing_tool #Calling the function that maps the hostsnames to the open ports from the portscan XML report
	python3 $tools_dir/python-parse.py > $portscans_dir/nuclei-hosts.txt
	nuclei -up
	nuclei -ut
	nuclei -l $portscans_dir/nuclei-hosts.txt -v -o $nuclei_report_dir/nuclei-report
}



#This function is used in the Nuclei script to create the python script that parses the NMAP XML into hostnames with their open ports. 
#This is needed for nuclei to scan by domain name and not IP address.
function create_python_parsing_tool {

	if [ ! -f "$tools_dir/python-parse.py" ]; then
cat <<EOF > $tools_dir/python-parse.py
import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        hostname = "unknown"
        for hostname_elem in host.findall("hostnames/hostname"):
            hostname = hostname_elem.get("name", "unknown")

        for port in host.findall("ports/port"):
            if port.find("state").get("state") == "open":
                portid = port.get("portid")
                protocol = port.get("protocol")
                results.append(f"{hostname}:{portid}/{protocol}")

    return results

file_path = "$portscans_dir/web-ports.xml"
parsed_results = parse_nmap_xml(file_path)

for result in parsed_results:
    print(result)
EOF
fi

chmod +x $tools_dir/python-parse.py
}


function perform_nmap_for_webservices {

echo -e '\n\n########################################################################################################\n######################## RUNNING NMAP SCAN FOR COMMON WEB SERVICES #####################################\n########################################################################################################\n\n'

nmap -iL $subdomain_dir/subdomains.txt -p10000,1010,10161,10162,10250,1099,110,1129,1131,11371,11751,1184,12013,12109,12443,1311,135,14143,143,15002,15672,16080,16993,16995,17778,18091,18092,20003,20720,2082,2083,2087,2089,2095,2096,21,22,2221,2252,2376,2381,2478,2479,2480,2482,2484,25,261,2679,271,2762,28017,300,3000,3077,3078,3128,3183,3191,32000,3220,324,3269,3306,3333,3410,3424,3471,3496,3509,3529,3535,3539,3660,36611,3713,3747,3766,3864,3885,3896,3995,4031,4036,4062,4064,4081,4083,4116,41230,4243,4335,4336,443,448,4536,4567,4590,465,4711,4712,4740,4843,4849,4993,5000,5007,5061,5104,5108,5280,5281,5321,5349,5443,55672,5601,563,5671,5783,5800,5868,591,593,5986,5989,5990,614,6209,6251,631,636,6443,6513,6514,6543,6619,664,6697,6771,684,695,7000,7001,7202,7396,7443,7474,7673,7674,7677,7775,80,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,81,8118,8123,8172,8181,8222,8243,8280,8281,832,8333,8337,8443,8500,853,854,8834,8880,8888,8983,8989,8991,9000,9001,9043,9060,9080,9089,9090,9091,9200,9295,9318,9443,9444,9502,9614,9800,9802,981,989,990,992,993,994,995,9981 -sC -vv -oA $portscans_dir/web-ports
}



#######################################################
#################### MAIN FUNCTION ####################
#######################################################
function start_script {


	#Ask if the user would like to install the dependencies
	answer="NA"
	read -p "Would you like to install dependencies? [N]: " answer
	#Ask if the user would like to brute with Jhaddix list
	answerJhaddix="NA"
	read -p "Would you like to brute force subdirectories with Jhaddix list(2 Million entries)? This may take a few hours [N]: " answerJhaddix
	answerNuclei="NA"
	read -p "Would you like to vulnerability scan with Nuclei? This may go out of scope [N]: " answerNuclei
	
	if [[ $answer == "y" || $answer == "Y" ]]; then
    		preflight_dependency_check
	fi
	
	#Run main functions	
	setup-directories
	perform_subfinder_enumeration
	if [[ $answerJhaddix == "Y" || $answerJhaddix == "y" ]]; then
		perform_gobuster_enumeration	
	fi
	perform_crtsh_subdomain_enumeration
	filter_live_hosts
	remove_duplicate_subdomains
	perform_nmap_for_webservices
	generate_html_portscan_report
	perform_aquatone
	if [[ $answerNuclei == "Y" || $answerNuclei == "y" ]]; then
		perform_nuclei_scan	
	fi
}

#######################################################
#################### KICKOFF ##########################
#######################################################
if [ "$EUID" -ne 0 ]; then
    echo -e "\nError\nThis script must be run with sudo."
    exit 1
elif [[ $# -lt 2 ]]; then
    echo "Usage: $0 <domain_name> <threads>"
    exit 1
elif [ -f $(pwd)/$1 ]; then
    echo "Usage: $0 <domain_name> <threads>"
    exit 1
else
	target_domain="$1"
	threads="$2"
        start_script
fi




########################
#########TO-DO##########
########################
#Implement Host and IP ownership - DONE
#Replace nmap with rustscan and scan all ports - DONE. Reverting back to NMAP. Rust doesent export XML correctly. (For now)










###############################################################################################
##################THESE FUNCTIONS ARE CURRENTLY UNUSED BUT MAY BE HANDY LATER##################
###############################################################################################
function create_URL_cleaning_script {

	if [ ! -f "$(pwd)/strip_url.sh" ]; then
			echo '#!/bin/bash
	url="$1"
	clean_url=$(echo "$url" | sed -E "s#^https?://##")
	echo "FUZZ.$clean_url"' > $(pwd)/strip_url.sh && chmod +x $(pwd)/strip_url.sh
		fi


}

function perform_rustscan_for_webservices {
		rustscan -a $subdomain_dir/subdomains.txt --range 1-1024 --batch-size 65535 --timeout 1000 --ulimit 5000 -- -sC -vv -oA $portscans_dir/web-ports
		echo -e '\n\n########################################################################################################\n######################## PORTSCANNING WITH RUSTSCAN ################################################\n########################################################################################################\n\n'
} 

#Combine the outputs from GoBuster and Subfinder
function perform_result_combination {

	cat "$target_file" "$subdomain_dir"/subfinder_output_*.txt "$subdomain_dir"/gobuster_dns_output_*.txt | grep -v 'Missed:'  | sed 's/Found: //' | sort -u > "$subdomain_dir"/combined_subdomains.txt
	echo "Subdomain enumeration completed. Combined results saved in: $subdomain_dir/combined_subdomains.txt"	
}

#This function Needs Work due to the error "DNS Servers received too many errors"
function perform_wordlist_mutations {
	
	cat "$subdomain_dir/combined_subdomains.txt" | parallel --line-buffer -j "$threads" --eta --bar 'clean_target=$(echo {} | tr -d "[:space:]" | tr -d "[:punct:]"); dmut -u {} -d $(pwd)/mutations.txt -w 25 --dns-timeout 1000 --dns-retries 5 --dns-errorLimit 25 --show-stats -o '"$subdomain_dir"'/dmut_output_{#}_results_$clean_target.txt'	
}


# Run httpx to find open ports on subdomains
function perform_webservice_portscan_with_httpx {
	cat "$subdomain_dir/subdomains.txt" | parallel --line-buffer -j "$threads" --eta --bar 'clean_target=$(echo {} | tr -d "[:space:]" | tr -d "[:punct:]"); echo {} | httpx -ports http:80,https:80,http:81,https:81,http:300,https:300,http:443,https:443,http:591,https:591,http:593,https:593,http:832,https:832,http:981,https:981,http:1010,https:1010,http:1311,https:1311,http:2082,https:2082,http:2087,https:2087,http:2095,https:2095,http:2096,https:2096,http:2480,https:2480,http:3000,https:3000,http:3128,https:3128,http:3333,https:3333,http:4243,https:4243,http:4567,https:4567,http:4711,https:4711,http:4712,https:4712,http:4993,https:4993,http:5000,https:5000,http:5104,https:5104,http:5108,https:5108,http:5800,https:5800,http:6543,https:6543,http:7000,https:7000,http:7396,https:7396,http:7474,https:7474,http:8000,https:8000,http:8001,https:8001,http:8008,https:8008,http:8014,https:8014,http:8042,https:8042,http:8069,https:8069,http:8080,https:8080,http:8081,https:8081,http:8088,https:8088,http:8090,https:8090,http:8091,https:8091,http:8118,https:8118,http:8123,https:8123,http:8172,https:8172,http:8222,https:8222,http:8243,https:8243,http:8280,https:8280,http:8281,https:8281,http:8333,https:8333,http:8443,https:8443,http:8500,https:8500,http:8834,https:8834,http:8880,https:8880,http:8888,https:8888,http:8983,https:8983,http:9000,https:9000,http:9043,https:9043,http:9060,https:9060,http:9080,https:9080,http:9090,https:9090,http:9091,https:9091,http:9200,https:9200,http:9443,https:9443,http:9800,https:9800,http:9981,https:9981,http:12443,https:12443,http:16080,https:16080,http:18091,https:18091,http:18092,https:18092,http:20720,https:20720,http:28017,https:28017 -o '"$subdomain_dir"'/httpx_output_{#}_$clean_target.txt'

	#Combine all httpx output files
	cat "$subdomain_dir"/httpx_output_*.txt | sort -u > "$subdomain_dir"/all_httpx_results.txt
	echo -e "\nPort scanning with httpx completed. Results saved in: $subdomain_dir \n"

	#Ask user if they want to edit the all_httpx_results.txt file to remove OOS targets, continue without editing, or quit the script
	while true; do
    		read -p "Do you want to edit the all_httpx_results.txt file to remove OOS targets before VHOST probing? (yes/no/quit): " edit_choice
    		case $edit_choice in
        		[Yy][Ee][Ss]|[Yy])
            			nano "$subdomain_dir"/all_httpx_results.txt
            			break
            			;;
        		[Nn][Oo]|[Nn])
            			break
            			;;
        		[Qq][Uu][Ii][Tt])
            			echo "Quitting the script."
            			exit
            			;;
        		*)
            			echo "Invalid choice. Please enter 'yes', 'no', or 'quit'."
            			;;
    			esac
		done
}

#Run ffuf on httpx results with VHOST enumeration
function perform_vhost_enumeration {

	cat "$subdomain_dir"/all_httpx_results.txt | parallel --line-buffer -j "$threads" --eta --bar './strip_url.sh {} | xargs -I % ffuf -w $(locate fierce-hostlist.txt) -H '\''Host: %'\'' -u {} | tee '"$subdomain_dir"'/ffuf_output_{#}_%$(./strip_url.sh {}).txt'
	echo "ffuf enumeration on httpx results completed. ffuf results saved in: $subdomain_dir"
}
