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

def init():

    if len(sys.argv) != 3:
        print("[!]NeedMoreArguments")
        print(f"[*]Usage: {sys.argv[0]} <lhost> <lport>")
        sys.exit()
    
    else:
        print(banner)
    
def step1():

    lhost = sys.argv[1]
    lport = sys.argv[2]
    host_n_port = [lhost,lport]
    print(f"[>]YourIP: {lhost} [>]Port: {lport}")
    return host_n_port

    del lhost,lport,host_n_port

def line_maker(arg1,arg2):
    header = "+"+"-"*len(arg1)+"+"+"-"*len(arg2)+"+"
    middle = "|"+arg1+"|"+arg2+"|"
    footer = "+"+"-"*len(arg1)+"+"+"-"*len(arg2)+"+"
    
    print(header)
    print(middle)
    print(footer)

    del header,middle,footer

def step2():
    
    array = []
    for i in dir(napalm):
        if "__" not in i:
            array.append(i)

    return array
    del array

def step3(array):
    
    counter = 0

    for i in array:
        line_maker(str(counter),i)
        counter += 1
        
    print("[+]Select the Number of payload")
    
    while True:
        chose = input("> ")
        
        reg = re.search(r"\d.*",chose)
        if reg != None:
            break
    
    return chose


def main():
    init()
    host_n_port = step1()
    array = step2()    
    step3(array)

if __name__ == "__main__":

    main()
