import nmap3
import nmapthon as nm
import json
import socket

nmap = nmap3.Nmap()

response = input("""\nPlease enter the type of scan you want to run
                1) Scan Open Ports
                2) Get Vulnerabilities
                3) OS Detection\n""")
print("You have selected option: ", response)

if response == '1':
   print("****************************************")
   print("***START: Scanning ports on my Network****")
   print("****************************************")

   #IP Address to scan
   #ipAddr = "127.0.0.1"
   hostname = input("Please enter website address:\n")
   ipAddr = socket.gethostbyname(hostname)
   #ipAddr = input("Enter ipAddress to Scan:- ")

   #scanPorts='22,53,443,135,445,5357,5000'
   #scanPorts='21-25'
   scanPorts = input("Enter Ports to scan:- ")

   if ipAddr == "":
    ipAddr = "127.0.0.1"
   if scanPorts == "":
    scanPorts='22,53,443,135,445,5357,5000'
   
   scanner = nm.NmapScanner(ipAddr,ports=scanPorts, arguments='-O --osscan-guess')
   scanner.run()
 
   for host in scanner.scanned_hosts():
     # Get state, reason and hostnames
     print("Host: {}\tState: {}\tReason: {}".format(host, scanner.state(host), scanner.reason(host)))
     print("Hostname: {}".format(','.join(scanner.hostnames(host))))
     # Get scanned protocols
     for proto in scanner.all_protocols(host):
        # Get scanned ports
        for port in scanner.scanned_ports(host, proto):
            service = scanner.service(host, proto, port)
            print("Service name: {}".format(service.name))
            print("______________________________________")
            state, reason = scanner.port_state(host, proto, port)
            print("Port: {0:<7}State:{1:<9}Reason:{2}".format(port, state, reason))
            print("______________________________________")
           
   print("****************************************")
   print("***END: Scanning ports on my Network****")
   print("****************************************")

elif response == '2':
   print("****************************************")
   print("***START: Vulnerability Detection****")
   print("****************************************")
   
   #scanSite= "www.tataaia.com"
   scanSite = input("Enter Site to scan Vulnerabilities :- ")

   if scanSite == "":
    scanSite = "www.taboola.com"
   
   print('Please wait - Vulnerability Scan is in Progress...',scanSite)
   ressults1 = nmap.nmap_version_detection(scanSite, args="--script vuln -p 443")
     
 
   json_str = json.dumps(ressults1)
   resp = json.loads(json_str)
   myKey = resp.keys()
   print(list(myKey)[0])
   mykeyN = list(myKey)[0]
   print("-----")
   print(json.dumps(resp[mykeyN]["ports"][0]["scripts"], indent=4))
   print("-----")

   print("****************************************")
   print("***END: Vulnerability Detection****")
   print("****************************************")


elif response == '3':
   print("****************************************")
   print("***START: Finger Print & OS Detection****")
   print("****************************************")

   #IP Address to scan
   #ipAddr = "127.0.0.1"
   ipAddr = input("Enter ipAddress to Scan:- ")

   #scanPorts='22,53,443,135,445,5357,5000'
   #scanPorts='21-25'
   #scanPorts = input("Enter Ports to scan:- ")

   if ipAddr == "":
    ipAddr = "127.0.0.1"
   #if scanPorts == "":
    #scanPorts='22,53,443,135,445,5357,5000'

   scanner = nm.NmapScanner(ipAddr, arguments='-O --osscan-guess')
   scanner.run()

   for os_match, acc in scanner.os_matches(ipAddr):
    print('OS Match: {}\tAccuracy:{}%'.format(os_match, acc))

   fingerprint = scanner.os_fingerprint(ipAddr)
   if fingerprint is not None:
    print('Fingerprint: {}'.format(fingerprint))
   else:
    print('Fingerprint: ',"None")

   for most_acc_os in scanner.most_accurate_os(ipAddr):
    print('Most accurate OS: {}'.format(most_acc_os))

   print("****************************************")
   print("***END: Finger Print & OS Detection****")
   print("****************************************")
else:
   print("Please choose a number from the options above")
