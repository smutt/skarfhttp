Skarf HTTP traffic and spit up useful nibbles and bytes 


USAGE:  
    skarfhttp [FLAGS] [OPTIONS] --iface <IFACE>  

FLAGS:  
        --help           Prints help information  
    -l, --line-output    print all output on one comma delimited line  
    -t, --timestamp      prepend 64-bit UNIX timestemp to output  
    -V, --version        Prints version information  
  
OPTIONS:  
    -C, --chop <BYTES>             Chop BYTES from beginning of every packet  
    -d, --delimiter <DELIMITER>    Use custom delimiter [default: ,]  
    -h, --headers <headers>        Lowercase list of HTTP headers to print e.g. user-agent,cookie  
    -i, --iface <IFACE>            pcap interface to listen on, typically a network interface  
    -j, --json <KEY>               When content-type includes string 'json', print [boolean|number|string] values of  
                                   these json keys  
    -p, --port <PORT>              TCP port for bpf filter [default: 80]  
    -q, --requests <requests>      List of request methods to match e.g. GET,POST [default: GET,POST]  
    -s, --responses <responses>    List of response statuses to match e.g. 200,404  
