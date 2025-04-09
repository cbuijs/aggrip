
Some IP-Address and DNS domainname based tools.


aggrip.py
Aggregate IP-Addresses/CIDR list into a CIDR based list


range2cidr.py
Convert/Aggregate IP-Ranges list (192.168.1.0-192.168.1.255 syntax) into a CIDR based list


revip.py
Convert an IP-Address/CIDR list into reverse in-addr/ip6.arpa syntax DNS names.


undup.py
Unduplicate DNS domain-list by removing unneeded sub-domains when parent domain exists.


domsort.py
Sort domain-list from root down (tree wise).


====== NOTE:
The tools do not accept any command-line parameters, just pipe data into them like:

     "cat file.txt | ./aggrip.py".

