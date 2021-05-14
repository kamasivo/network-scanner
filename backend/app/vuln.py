import nmap
import pandas as panda

# function for finding vulnerabilities
# we use pandas to save into json file
def find_vulnerabilities():
    print("Start nmap script scan to find vulnerabilities.")

    nmScan = nmap.PortScanner()  
    nmScan.scan('192.168.1.220', arguments='-sV -script vulners')    # call script
    vuln_list = [[]]                                                 # list where vulnerabilities are saved before saving in file
    for host in nmScan.all_hosts():
        if('tcp' in nmScan[host]):
            for port in nmScan[host]['tcp']:
                if('script' in nmScan[host]['tcp'][port]):
                    if('vulners' in nmScan[host]['tcp'][port]["script"]):
                        vuln_list.append([host, port, nmScan[host]['tcp'][port]["state"],
                        nmScan[host]['tcp'][port]["name"], nmScan[host]['tcp'][port]["product"],
                        nmScan[host]['tcp'][port]["script"]['vulners']])   
                else:
                    vuln_list.append([host, port, nmScan[host]['tcp'][port]["state"], 
                    nmScan[host]['tcp'][port]["name"], nmScan[host]['tcp'][port]["product"], ""]) 
        vuln_list.append([host, "", "", "", "", ""]) 
    panda.DataFrame(vuln_list, columns=['ipAddress', 'port', 'state', 'name', 'product', 'script']).to_json("networkdata/vulns.json", orient="table")

