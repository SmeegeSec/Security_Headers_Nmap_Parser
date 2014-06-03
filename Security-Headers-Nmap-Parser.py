"""
Name:           Security Headers Nmap Parser
Version:        0.20
Date:           5/30/2014
Author:         Smeege
Contact:        SmeegeSec@gmail.com

Description:    Security-Headers-Nmap-Parser.py is a python script written to parse and display the results of nmap .xml output files.  
		If the '--script=http-headers' argument is specifed an html report will be generated with each row being an individual
		ip:port and which security headers it responded with.  The motivation behind this script was to provide a clean report
		and clear look at which assets in an environment respond with which security headers.

Logic:
		access-control-allow-origin: *		#bad, allows cross-site requests from any domain.  null or specify domain is good.
		content-security-policy			#good, define scripts,media,stylesheets,etc. that can run.  whitelist resources.
		x-permitted-cross-domain-policies	#good, specify which policy files to follow (http://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf)
		x-content-type-options			#good, reject responses with incorrect MIME types.  MIME types must match script and stylesheet resources.
		server				        #bad, dont need to expose server information
		strict-transport-security		#good, specify browsers should request https version of content
		x-frame-options				#good, disallow framing by other sites. three options: deny, sameorigin, allow-from
		x-powered-by				#bad, dont need to expose software information
		x-xss-protection: 0			#bad, protection disabled
		x-xss-protection: 1			#good, modifies response to break up potential script attacks
		x-xss-protection: 1; mode=block		#good, prevents whole page from rendering if potential attack is detected
"""
import argparse
import os
import sys
import re
from xml.dom import minidom

parser = argparse.ArgumentParser(prog='Security-Headers-Nmap-Parser.py', usage='%(prog)s {-f file} [-o output_file]')
parser.add_argument("-f", "--file", type=str, required=True, help="Parse a single Nmap .xml output file")
parser.add_argument("-o", "--output", type=str, help="Filename of output file for HTML report")
args = parser.parse_args()

#Check and create input and output files
if not os.path.isfile(args.file):
	print '\nThere was an error opening file: %s' % args.file
	sys.exit()

if args.output:
	if args.output.endswith('.html'):
                outFile = open(args.output, 'w')
	else:
		outFile = open(args.output + '.html', 'w')
else:
	outFile = open('Security-Headers-Report.html', 'w')

xmlDoc = minidom.parse(args.file)
hostList = xmlDoc.getElementsByTagName('host')

#List of security headers which are checked for and reported on
headerList = ['access-control-allow-origin', 'content-security-policy', 'server', 'strict-transport-security', 'x-content-type-options', 'x-frame-options', 'x-permitted-cross-domain-policies', 'x-powered-by', 'x-xss-protection' ]
assetDict = dict()

print '\nInput File: %s' % args.file
print 'Output File: %s' % outFile.name

outFile.write('<html>\n<head>\n<title>Security Headers Report</title>\n<style>\ntable,th,td\n{\nborder:1px solid black; text-align:center; font-size:85%; letter-spacing:1px\n}\np\n{\nfont-size:85%; margin: 5; padding: 0;\n}\nh5\n{\nmargin: 0; padding: -5;\n}\nh6\n{\nmargin: 0; padding: 0;\n}\n</style></head>\n<body>\n<table>')
outFile.write('<tr><th></th><th bgcolor="F2F2F2">access-control-allow-origin</th><th bgcolor="F2F2F2">content-security-policy</th><th bgcolor="F2F2F2">server</th><th bgcolor="F2F2F2">strict-transport-security</th><th bgcolor="F2F2F2">x-content-type-options</th><th bgcolor="F2F2F2">x-frame-options</th><th bgcolor="F2F2F2">x-permitted-cross-domain-policies</th><th bgcolor="F2F2F2">x-powered-by</th><th bgcolor="F2F2F2">x-xss-protection</th></tr>')

#Parse the Nmap .xml file. Create a dictionary where each key is a specific host:port, and each value is a list of found security headers
for host in hostList:
	for hostChildNode in host.childNodes[6].childNodes:
		if hostChildNode.nodeName == 'port' and hostChildNode.childNodes[0].attributes['state'].value == 'open':
			asset =  host.childNodes[2].attributes['addr'].value + ':' + hostChildNode.attributes['portid'].value
			for portChildNode in hostChildNode.childNodes:
				if portChildNode.nodeName == 'script' and portChildNode.attributes['id'].value == 'http-headers':
					foundHeaders = []
					for headerLine in str(portChildNode.attributes['id'].value + ':' + portChildNode.attributes['output'].value).split('\n  '):
						if headerLine.lower().split(':')[0] in headerList:
							foundHeaders.append(headerLine.lower())
					assetDict[asset] = foundHeaders

for asset in sorted(assetDict.keys(), key=lambda line: map(int, re.split(r'\.|:', line.strip()))):
	securityHeaders = assetDict[asset]
	securityHeadersString = "\n".join(securityHeaders)

	outFile.write('<tr>\n<td bgcolor="F2F2F2"><b>%s</b></td>' % asset)

	if 'access-control-allow-origin: *' in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D">Defined, <b>Allows All (*)</b></td>')
	elif 'access-control-allow-origin' not in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')
	else:
		outFile.write('<td bgcolor="80FF80">Defined, %s</td>' % re.search('access-control-allow-origin: (.*)', securityHeadersString).group(1))
	
	if 'content-security-policy' in securityHeadersString:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('content-security-policy: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')

	if 'server' in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D">Defined, %s</td>' % re.search('server: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="80FF80">Undefined</td>')

	if 'strict-transport-security' in securityHeadersString:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('strict-transport-security: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')

	if 'x-content-type-options' in securityHeadersString:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('x-content-type-options: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')

	if 'x-frame-options' in securityHeadersString:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('x-frame-options: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')

	if 'x-permitted-cross-domain-policies' in securityHeadersString:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('x-permitted-cross-domain-policies: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')

	if 'x-powered-by' in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D">Defined, %s</td>' % re.search('x-powered-by: (.*)', securityHeadersString).group(1))
	else:
		outFile.write('<td bgcolor="80FF80">Undefined</td>')
	
	if 'x-xss-protection: 0' in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D"><b>Protection Disabled,</b> x-xss-protection: 0</td>')
	elif 'x-xss-protection' not in securityHeadersString:
		outFile.write('<td bgcolor="FF4D4D">Undefined</td>')
	else:
		outFile.write('<td bgcolor="80FF80">%s</td>' % re.search('x-xss-protection: (.*)', securityHeadersString).group(1))

headersDescription = """<br><br>\n<h5>Access Control Allow Origin (Access-Control-Allow-Origin)</h5>\n<p>
Modern websites often include content dynamically pulled in from other sources online. SoundCloud, Flickr, Youtube and many other important websites use a technique called Cross Object Resource Sharing (CORS) to do so. Access Control Allow Origin is a header that is part of the "conversation" between the site a that wants to include data from another site.
</p>\n<h5>Content Security Policy (Content-Security-Policy)</h5>\n<p>Content Security Policy (CSP) prevents cross site scripting by explicitly declaring to browsers which script, media, stylesheets, etc are supposed to be run from your website. By whitelisting these resources, if an attacker is ever able to embed his evil code on your site, the browser will ignore it and visitors to your site will remain safe.
</p>\n<h5>Cross Domain Meta Policy (X-Permitted-Cross-Domain-Policies)</h5>\n<p>This header tells Flash and PDF files which Cross Domain Policy files found on your site can be obeyed; yes, it's a policy about other policies!</p>
</p>\n<h5>Content Type Options (X-Content-Type-Options)</h5>\n<p>Microsoft Internet Explorer (IE) and Google Chrome have the ability to guess the type of content may be found in a file, a process called "MIME-sniffing". Since the browser can be tricked by an attacker into making the incorrect decision about types of files it sees online, webmasters can tell IE/Chrome to not to sniff. That directive is called "nosniff" and it's communicated to via HTTP headers.</p>
</p>\n<h5>Server Information (Server)</h5>\n<p>The principle of least privilege says you only get access to stuff you need access to. Often times there is no reason for a server to advertise its information via headers.  Removing the server header won't stop attacks but can make them slightly more difficult.</p>
</p>\n<h5>Strict Transport Security (Strict-Transport-Security)</h5>\n<p>Using the HSTS header tells browsers that they should first make requests to your site over HTTPS by default!</p>
</p>\n<h5>Frame Options (X-Frame-Options)</h5>\n<p>The X Frame Options header is designed to minimize the likelihood that an attacker can use a clickjacking attack against your site. In a clickjacking attack, the bad guy places a frame that invisibly renders your site over top of some other content below that is tempting for users to click on. </p>
</p>\n<h5>Powered By Information (X-Powered-By)</h5>\n<p>The principle of least privilege says you only get access to stuff you need access to. Often times there is no reason to advertise your software version information via headers.  Removing the x-powered-by header won't stop attacks but can make them slightly more difficult.</p>
</p>\n<h5>XSS Protection (X-XSS-Protection)</h5>\n<p>Tells browsers such as IE and Chrome to be even more strict when they suspect an xss attack.  The header can designate the browser to not render the page, try to remove/encode dangerous characters, or provide no additional protection.</p>
<h6>Descriptions provided by <a href="https://securityheaders.com">https://securityheaders.com</a></h6>
"""
outFile.write('</table>')
outFile.write(headersDescription)
outFile.write('\n</body>\n</html>')
