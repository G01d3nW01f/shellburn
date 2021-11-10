#!/usr/bin/python3

from shellpalm import napalm
#from shellpalm import payload

import os
import re
import sys

banner = """
 (                                              
 )\ )    )       (   (    (                     
(()/( ( /(    (  )\  )\ ( )\    (   (           
 /(_)))\())  ))\((_)((_))((_)  ))\  )(    (     
(_)) ((_)\  /((_)_   _ ((_)_  /((_)(()\   )\ )  
/ __|| |(_)(_)) | | | | | _ )(_))(  ((_) _(_/(  
\__ \| ' \ / -_)| | | | | _ \| || || '_|| ' \)) 
|___/|_||_|\___||_| |_| |___/ \_,_||_|  |_||_|  
--------------------------------------------------
reverse_shell_payload_generator_
"""

class bcolors:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'

def red():
    print(bcolors.RED)

def endc():
    print(bcolors.ENDC)
   
def init():

    if len(sys.argv) != 3:
        red()
        print("[!]NeedMoreArguments")
        print(f"[*]Usage: {sys.argv[0]} <lhost> <lport>")
        endc()
        sys.exit()
    
    else:
        red()
        print(banner)
        endc()
def step1():

    lhost = sys.argv[1]
    lport = sys.argv[2]
    host_n_port = [lhost,lport]
    print(f"[>]YourIP: {lhost} [>]Port: {lport}")
    return host_n_port
    print(bcolors.GREEN)

    del lhost,lport,host_n_port

def line_maker(arg1,arg2):
    
    header = "+"+"-"*len(arg1)+"+"+"-"*len(arg2)+">>"
    middle = "|"+arg1+"|"+arg2+"."
    #footer = "+"+"-"*len(arg1)+"+"+"-"*len(arg2)+"+"
    
    print(header)
    print(middle)
    #print(footer)

    del header,middle
    
def step2():
    
    array = []
    for i in dir(napalm):
        if "__" not in i:
            array.append(i)

    array.remove("push_payload")

    return array
    del array

def step3(array):
    
    counter = 0
    print(bcolors.GREEN)
    for i in array:
        line_maker(str(counter),i)
        counter += 1
     
    spacer = len(array[len(array)-1])
    print("+-+"+"-"*spacer+">>")
    print(bcolors.ENDC)
    print("[+]Select the Number of payload")
    
    while True:
        chose = input("> ")
        
        reg = re.search(r"\d.*",chose)
        if reg != None:
            break
    
    return chose
    
def step4(host_n_port,array,chose):

    lhost,lport = host_n_port
    selected = array[int(chose)]
    print(f"[>]Selected: {selected}")
    cmd = "napalm."+selected+"(lhost,lport)"

    exec(cmd)
    
def main():

    init()
    host_n_port = step1()
    array = step2()    
    chose = step3(array)
    step4(host_n_port,array,chose)

if __name__ == "__main__":

    main()
