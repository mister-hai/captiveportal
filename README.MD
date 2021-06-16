#Captive Portal tool

    λ python captiveportal.py --help
     [+] Database Loaded! 
     [+] Parsing Command Line Arguments 

    usage: captiveportal.py [-h] [--target TARGET] [--wget_options WGET_OPTIONS] 
                        [--user-agent USERAGENT] [--directory_prefix DIRECTORY_PREFIX]
                        [--monitor_iface MONIFACE] [--ethernet_iface IFACE] [--NAT_iface NAT_IFACE]
                        [--filename FILENAME] [--port PORT] [--portal_page INDEX]
                        [--htmldirectory HTMLDIRECTORY] [--bad BAD] [--debug DEBUG]

optional arguments:
    -h, --help            show this help message and exit
    --target TARGET       Website to mirror, this is usually the only option you should set. 
                        Multiple downloads will be stored in thier own directories, ready 
                        for hosting internally.

    --wget_options WGET_OPTIONS
                        Wget options, Mirroring to a subdirectory is the default 
                        DEFAULT : -nd -H -np -k -p -E

    --user-agent USERAGENT
                        User agent to bypass crappy limitations 
                        DEFAULT : Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101      
                            Firefox/28.0

    --directory_prefix DIRECTORY_PREFIX
                        Storage dirctory to place the downloaded files in, defaults to script
                        working directory

    --monitor_iface MONIFACE
                        The interface name of the Interface in monitor mode

    --ethernet_iface IFACE
                        Outward facing interface, the one that connects to the internet

    --NAT_iface NAT_IFACE
                        Inward facing interface, the one that will handle clients 
                        in the network you create

    --filename FILENAME   Filename to use for database

    --port PORT           Port you are serving the HTML/captive portal from

    --portal_page INDEX   index page to serve

    --htmldirectory HTMLDIRECTORY
                        directory the captive portal index is in

    --bad BAD             Will determine if this is an insecure tool of destruction 
                          or a useful tool ofnetworking
  
    --debug DEBUG         Verbose Output and Debug Pages are enabled with this 
                        "Default : On " option
