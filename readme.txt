HTTP Security Headers Nmap Parser is a python script which parses Nmap's .xml output and will generate a .html report based on HTTP security-related headers.

Steps:
	1.	Run Nmap with http-headers script and xml output: nmap  --script=http-headers <target> -oX output_file.xml
	2.	Run Security-Headers-Nmap-Parser.py on the Nmap .xml file: python Security-Headers-Nmap-Parser_done -f output_file.xml