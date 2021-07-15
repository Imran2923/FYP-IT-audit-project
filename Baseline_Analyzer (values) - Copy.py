import pyfiglet
import fileinput
import time
from parse import *
import re

#module for patch scan
import os
import subprocess as sp

#module for port scan
import sys
import socket
from datetime import datetime

#import colors
from colorama import init, Fore
init() 
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

CGREEN  = '\33[32m'
CGREEN2  = '\33[92m'
CRED2   = '\33[91m'
CORANGE   = '\33[33m'
CBLUE   = '\33[44m'
CBLINK    = '\33[5m'
CORANGE2 = '\33[43m'
CBOLD     = '\33[1m'
CEND      = '\33[0m'
CYELLOW2 = '\33[93m'
CREDBG2    = '\33[101m'
CSELECTED = '\33[7m'

#main banner
banner = pyfiglet.figlet_format("FYP Integrated Tool")
print(banner)
print("-" * 50)
print("\n")

def windows():
    
    def adirectory():
        import time
        import configparser
        config = configparser.ConfigParser()
        time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
        timestr = time + " Windows Settings.txt"
        print ("Writing to", timestr)
        

        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
            #p_list = p_output.replace("-----------------", "=")
            #p_list = p_list.split("=")
            
            #p_dict = dict([p_list])
            #config['complexity'] = p_dict
        

        with open(timestr,'w') as configfile:
            print(p_output)
            
        #config.read(timestr)
        #print("\n")
        #if(config['complexity']['ComplexityEnabled'] == "True"):
            #print("No need to change Password setting: ComplexityEnabled \n")
        
        #else:
            #print("Setting 'ComplexityEnabled' requires change: False to True \n")
        
        #if((config['maxpage']['MaxPasswordAge']) == "42.00:00:00"):
            #print("No need to change Password setting: Maximum Password Age \n")
        
        #else:
            #print("Setting 'MaxPasswordAge' requires change: Equal to or more than 42.00 \n")
            
            
        #if(config['minpage']['MinPasswordAge'] == "1.00:00:00"):
            #print("No need to change Password setting: Minimum Password Age \n")
        
        #else:
            #print("Setting 'MinPasswordAge' requires change: Equal to or more than 1.00 \n")
            
        #print(config.sections())
        print("\n")
        main()

    def wbrowser():
        import time
        time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
        timestr = time + " Web Browser settings.txt"
        print ("Writing to", timestr)        
        
        with open(timestr, "w") as file:
            Password()
        
        main()
        
    def moffice():
        import time
        time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
        timestr = time + " Web Browser settings.txt"
        print ("Writing to", timestr)        
        
        with open(timestr, "w") as file:  
                Password()
                
        main()
        
    def msql():
        import time
        time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
        timestr = time + " Web Browser settings.txt"
        print ("Writing to", timestr)        
        
        with open(timestr, "w") as file:  
                Password()
                
        main()    
    
    def main():
        while True:
            try:
                option = input("Please select an option:\n\n"
                                    "1 - Windows settings\n"
                                     "2 - Web browser\n"
                                     "3 - MS Office\n"
                                     "4 - MS SQL server\n"
                                     "q - Quit\n"
                                     "\nEnter option: ")
            except ValueError:
                print("INvalid input")
    
            if option == 'q':
                print("Program exited")
                bigmain()
    
            elif int(option) == 1:
                adirectory()
                
    
                break
    
            elif int(option) == 2:
                
    
                break
    
            elif int(option) == 3:
                
    
                break    
            
            elif int(option) == 4:
                
    
                break        
    main()
    
def ubuntu():
      
        def patch_scan():
            #patch scan banner
            banner = pyfiglet.figlet_format("FYP PATCH SCANNER")
            print(banner)
            print("-" * 50)
            print("\n")
        
        
            print("Packages that have updates available")
            print("-" * 50)
        
            #list all pacakges that have updates available
        
            os.system('sudo /usr/lib/update-notifier/apt-check -p') 
            #os.system("sudo apt list --upgradable | grep -oP '^/\[%s+' ") #gets list of all upgradable packages 
        
            print("\n")
            print("-" * 50)
        
            #print("\n")
        
            #asks if would like to install packages
        
            #install = input("Install packages?(Y/N): ").lower()
        
            #if install == "y":
                #os.system("sudo apt-get update") #synchonize package index files from sources again
                #os.system("sudo apt-get upgrade") #install the latest versions of the packages currently installed on the user’s system 
                #print("Packages updated")
            #elif install == "n":
                #print("ok bye")
            #else:
                #print("invalid input")
        
        def port_scan():
            #port scan banner
            banner = pyfiglet.figlet_format("FYP PORT SCANNER")
            print(banner)
            print("-" * 50)
        
            #get target host
            target = input('Enter the host to be scanned: ')
        
        
            #Scanning feedback
            print("-" * 50)
            print("Scanning Target: " + target)
        
            #get start time of scan
            startTime = time.time()
        
            print("Scanning started at:" + str(format(datetime.now(),"%d/%m/%Y %H:%M:%S")))
            print("-" * 50)
        
            #scan
            try:
                # will scan ports between 1 to 1023 (well known TCP/UDP ports)
                for port in range(1,1023):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)
        
                    # returns an error indicator
                    result = s.connect_ex((target,port))
                    if result ==0:
                        print(f"{GREEN}[+] {target}: {port} is open      {RESET}")
                        #print("Port {}: OPEN".format(port))
                    s.close()
        
            except KeyboardInterrupt:
                print("\n Exitting Program !!!!")
                sys.exit()
            except socket.gaierror:
                print("\n Hostname Could Not Be Resolved !!!!")
                sys.exit()
            except socket.error:
                print("\ Server not responding !!!!")
                sys.exit()
        
            print("-" * 50)
        
            #print time taken for scan
            print('Time taken:', round((time.time() - startTime),3)," seconds")
            print("-" * 50)
            print("\n")
        def passwdaudit():
            #modules for password crack
            import crypt
            import hashlib
            from sys import argv  
            
            PASSWD_DICT = 'passwds.txt'  # path to password dictionary
            SHADOW_LOC = '/etc/shadow' # path to shadow file
        
            def pwmenu():
                while True:
                    try:
                        option = input("Please select an option:\n\n"
                                                "1 - Local password audit\n"
                                                 "2 - Remote password audit\n"
                                                 "q - Quit\n"
                                                 "\nEnter option: ")
                    except ValueError:
                        print("Invalid input")
        
                    if option == 'q':
                        print("Program exited")
                        ubuntumain()
        
                    elif int(option) == 1:
                        local_crack()
                        pwmenu()
        
                        #break
        
                    elif int(option) == 2:
                        remote_crack()
                        pwmenu()
                        break
        
        
            def local_crack():
            #get target host
        
                if os.access(SHADOW_LOC, os.F_OK): #Make sure Shadow file exists.
                    shadowRead = open(SHADOW_LOC, mode='r')
                    print ("Shadow Location: ", SHADOW_LOC) #print shadow file location
                    print("\nPlease specify a system user. \n")
                    user = input("Specify User Account: ")
                    userFound = False
                    for line in shadowRead.readlines(): #Make sure user exists
                        if (user in line):
                            userFound = True
                            print ("Selected User: ", user)
                            line = line.strip() #Remove blank space
                            line = line.replace("\n","").split(":")
                            if line[1] not in ['x','*','!']:
                                user = line[0].strip()
                                cryptPass = line[1].strip()
                                crack_hash(cryptPass, user)
                    if (userFound == False): #Alert if user does not exist
                        print ("User not found!")
                        print("-" * 50)
                        sys.exit()
                else: # Alert if shadow file does not exist
                    print ("Shadow file does not exist at ", SHADOW_LOC)		
                    print("-" * 50)
            def crack_hash(cryptPass, user):
                if os.access(PASSWD_DICT, os.F_OK): #Make sure password dictionary file exists
                    print ("\nPassword Dictionary: ", PASSWD_DICT)
                    passDict = open(PASSWD_DICT, 'r')
        
                    ctype = cryptPass.split("$")[1]
                    if ctype == '1':
                        print ("Hash type: MD5 \n")
                    elif ctype == '2a':
                        print ("Hash type: Blowfish\n ")
                    elif ctype == '5':
                        print ("Hash type: SHA-256 \n")
                    elif ctype == '6':
                        print ("Hash type: SHA-512 \n")
                    else:
                        print ("Unable to determine Hashing Algorithm \n")
        
                    #check for match
                    passFound = False
                    salt = cryptPass.split("$")[2]
                    insalt = "$" + ctype + "$" + salt + "$"
                    print ("\nCracking password for: ",user)
                    for word in passDict.readlines():
                        word = word.strip() #fixed
                        #word.strip()
                        #word.strip('\n')
                        cWord = crypt.crypt(word, insalt)
                        if (cWord == cryptPass):
                            passFound == True
                            print ("\nUsername:", user)
                            print ("Password:", word)
                            print("-" * 50)
                            pwmenu()
                    if (passFound == False):
                        print ("Password not in dictionary file", PASSWD_DICT)
                        print("-" * 50)
                else:
                    print ("Password Dictionary does not exist!")
                    print("-" * 50)
        
            def remote_crack():
                #command =  'ssh '+rhost_user+'@'+rhost_ip
                #os.system("ssh ubuntu@192.168.77.131")
        
        
                ##WIP##
                user = input("Enter remote user: ")
                host = input("Enter remote host IP address: ")
                password = input("Enter remote host password: ")
        
                port = 22
        
                command = "sudo cat /etc/shadow"
        
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port, user, password=password)
        
                stdin, stdout, stderr = ssh.exec_command(command)
                lines = stdout.readlines()
                print(lines)
                print("-------------------------------")
        
        
            if __name__ == '__main__':
                pwmenu()	
            
        def ubuntumain():
            while True:
                try:
                    option = input("Please select an option:\n\n"
                                        "1 - Patch scan\n"
                                         "2 - Port scan\n"
                                         "3 - Password audit\n"
                                         "q - Quit\n"
                                         "\nEnter option: ")
                except ValueError:
                    print("INvalid input")
        
                if option == 'q':
                    print("Program exited")
                    bigmain()
        
                elif int(option) == 1:
                    patch_scan()
                    ubuntumain()
                    break
        
                elif int(option) == 2:
                    port_scan()
                    ubuntumain()
                    break
        
                elif int(option) == 3:
                    passwdaudit()
                    ubuntumain()
                    break    
        
        
        ubuntumain()    
    

def centos():
    output = sp.getoutput("figlet Centos 8")
    print(output)
    result2 = "\033[1m" + "\n[----------------------------Result----------------------------]" + "\033[0m"
    
    
    def centOS_cis_benchmarks():    
        print("1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)") 
    
    
    def initial_setup_scan():
        #1.1.1.1 Ensure mounting of cramfs filesystems is disabled
    
        print(result2)
    
        outputCramfsCMD = sp.check_output("modprobe -n -v cramfs", shell=True).decode(sys.stdout.encoding).strip()
        outputCramfsCMD2 = sp.getoutput("lsmod | grep cramfs") 
    
        #print(outputCMD)
        #print(outputCMD2) 
    
        if outputCramfsCMD == "install /bin/true" and outputCramfsCMD2 == outputCramfsCMD2: 
            print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)")
        else: 
            print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)") 
    
    
        #Ensure sudo is installed 
        outputSudoCMD = sp.getoutput("rpm -q sudo")
        #print(outputSudoCMD) 
    
        fullstring = outputSudoCMD
        substring = "sudo"
    
        if substring in fullstring:
            print("\033[1m" + "Status: "  + CGREEN + "[PASS] " + "\033[0m" + "1.3.1 Ensure sudo is installed (Scored)")
        else: 
            print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] "  + "\033[0m" + "1.3.1 Ensure sudo is installed (Scored)") 
    
    
        #1.2.3 Ensure package manager repositories are configured (Not Scored)
    
    
    def service_scan():
        ouputXinetedCMD = sp.getoutput("rpm -q xinetd")
    
        print(result2)
    
        if ouputXinetedCMD == "package xinetd is not installed":
            print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "2.1.1 Ensure xinetd is not installed (Scored)")
        else: 
            print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "2.1.1 Ensure xinetd is not installed (Scored)")
            sp.run("sudo dnf remove -yq xinetd", shell=True)
            print("\033[1m" + "Status: " + CGREEN2 + "[SUCCESSFUL] " + "\033[0m" + "Xinetd has been successfully uninstalled.") 
    
    
    
        #*****
        #2.2.9 Ensure HTTP server is not enabled (Scored)
        #*****        
        print(CSELECTED+"\n[Control] 2.2.9 Ensure HTTP server is not enabled (Scored)")
        outputSER1 = sp.getoutput("systemctl is-enabled httpd")
    
        if outputSER1 == "disabled":
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "2.2.9 Ensure HTTP server is not enabled (Scored)")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "2.2.9 Ensure HTTP server is not enabled (Scored)")
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 2.2.9 Ensure HTTP server is not enabled (Scored)] " + "\033[0m")
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m"  + outputSER1) 
    
    
        #*****
        #2.2.7 Ensure Samba is not enabled (Scored)
        #*****    
    
    
    
    def network_configuration_scan():
        #3.1.1 Ensure IP forwarding is disabled (Scored) 
        #Rationale - Setting the flags to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.
        outputNCS1 = sp.getoutput("sysctl net.ipv4.ip_forward")
        outputNCS2 = sp.getoutput("grep -E -s '^\s*net\.ipv4\.ip_forward\s*=\s*1' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf")
        outputNCS3 = sp.getoutput("sysctl net.ipv6.conf.all.forwarding")
        outputNCS4 = sp.getoutput("grep -E -s '^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf")
    
    
        print(CSELECTED+"\n3.1.1 Ensure IP forwarding is disabled (Scored) ")    
    
        if outputNCS1 == "net.ipv4.ip_forward = 0" and outputNCS2 is None and outputNCS3 == "net.ipv6.conf.all.forwarding = 0" and outputNCS4 is None:
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "3.1.1 Ensure IP forwarding is disabled (Scored) ")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "3.1.1 Ensure IP forwarding is disabled (Scored) ")
    
    
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 3.1.1 Ensure IP forwarding is disabled (Scored)] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\nIPv4: " + outputNCS1 + outputNCS2 + "\nIPv6: " +outputNCS3 + outputNCS4) 
        
        
        
        #3.1.2 Ensure packet redirect sending is disabled (Scored)#
        #Rationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an 
        #attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
    
        print(CSELECTED+"\n3.1.2 Ensure packet redirect sending is disabled (Scored)")    
        
        outputNCS5 = sp.getoutput("sysctl net.ipv4.conf.all.send_redirects")
        outputNCS6 = sp.getoutput("sysctl net.ipv4.conf.default.send_redirects")
        outputNCS7 = sp.getoutput("grep 'net\.ipv4\.conf\.all\.send_redirects' /etc/sysctl.conf")
        outputNCS8 = sp.getoutput("grep 'net\.ipv4\.conf\.default\.send_redirects' /etc/sysctl.conf")
    
        
        if outputNCS5 == "net.ipv4.conf.all.send_redirects = 0":
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "3.1.2 Ensure packet redirect sending is disabled (Scored)")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "3.1.2 Ensure packet redirect sending is disabled (Scored)")
            
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 3.1.1 Ensure IP forwarding is disabled (Scored)] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m") 
        print(outputNCS5)
        print(outputNCS6)
        print(outputNCS7)
        print(outputNCS8)     
            
                
        
        
    
    def logging_auditing():
        #4.1.1.1 Ensure auditd is installed (Scored)
        print(result2)
    
        print(CBOLD + "\n[Control] 4.1.1.1 Ensure auditd is installed (Scored)")
    
        outputLA1 = sp.getoutput("rpm -q audit audit-libs")
        substring = "audit"
    
        if substring in outputLA1:
            print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "4.1.1.1 Ensure auditd is installed (Scored)")
        else:
            print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "4.1.1.1 Ensure auditd is installed (Scored)")
            runLA1 = sp.run("dnf install -y audit audit-libs")
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 4.1.1.1 Ensure auditd is installed (Scored)]" + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\n" +  outputLA1)  
    
    
        #4.1.1.2 Ensure auditd service is enabled (Scored)
        outputLA2 = sp.getoutput("systemctl is-enabled auditd")
        print(CBOLD + "\n[Control] 4.1.1.2 Ensure auditd service is enabled (Scored)")
    
        if outputLA2 == "enabled":
            print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "4.1.1.2 Ensure auditd service is enabled (Scored)")
        else:
            print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "4.1.1.2 Ensure auditd service is enabled (Scored)")
            runLA2 = sp.run("systemctl --now enable auditd" , shell=True)
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 4.1.1.2 Ensure auditd service is enabled (Scored)" + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\nStatus: " +  outputLA2)          
    
    
    
    
    def a_a_a_C():
    
        #User inputs
        print(CSELECTED + CBOLD + "\n[Control] 5.5.1.1 Ensure password expiration is [] days or less (Scored)")
    
        userIN1 = input(CEND+'Enter password expiration days: ')
    
        print(CSELECTED + CBOLD + "\n[Control] 5.5.1.2 Ensure minimum days between password changes is [] or more (Scored) - Site Policy") 
        userIN2 = input(CEND+'Enter minimum days between password changes: ')
    
        print(CSELECTED + CBOLD + "\n[Control] 5.5.1.2 Ensure minimum days between password changes is [] or more (Scored) - All Users")
        userIN3 = input(CEND+'Enter minimum days between password changes:  ')
    
        print(CSELECTED + CBOLD +  "\n[Control] 5.5.1.3 Ensure password expiration warning days is [] or more (Scored) - Site Policy")
        userIN4 = input(CEND + 'Enterpassword expiration warning days: ')
    
        print(CSELECTED + CBOLD +  "\n[Control] 5.5.1.3 Ensure password expiration warning days is [] or more (Scored) - All Users")
        userIN5 = input(CEND+ 'Enterpassword expiration warning days: ')
    
        print(CSELECTED + CBOLD + "\n[Control] 5.5.1.4 Ensure inactive password lock is [] days or less (Scored) -  All Users")
        userIN6 = input(CEND +'Enter inactive password lock days: ')
    
    
    
        print(result2)
    
        #5.2.3 Ensure permissions on SSH private host key files are configured (Scored)
        #Rationale - If an unauthorized user obtains the private SSH host key file, the host could be impersonated
    
        result3 = "\033[1m" + "\n[Result - Access, Authentication and Authorization]" + "\033[0m"
        print(result3)
    
    
        print(CSELECTED+"\n[Control] 5.2.3 Ensure permissions on SSH private host key files are configured (Scored)")
        print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.3 Ensure permissions on SSH private host key files are configured (Scored)")
        outputSSH523 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep Gid")
        print(outputSSH523) 
    
    
        outputSSH524 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;");  
        outputSSH25 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;")    
    
    
        #5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
        print(CSELECTED+"\n[Control] 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
        outputSSH27 = sp.getoutput("sudo sshd -T | grep -oP '(?<=maxauthtries).*'")
    
        if int(outputSSH27) <= 4:
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
    
    
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " MaxAuthTries" +outputSSH27)
    
    
        #5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
        print(CSELECTED+"\n[Control] 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        outputSSH28 = sp.getoutput("sudo sshd -T | grep -oP '(?<=ignorerhosts).*' ")
        #print(outputSSH28) 
    
        if outputSSH28 == " yes":
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " IgnoreRhosts" +outputSSH28)
    
    
        #5.4.1 Ensure password creation requirements are configured (Scored)
    
        print(CSELECTED + "\n[Control] 5.4.1 Ensure passsqword creation requirements are configured (Scored)")
        #provide at least one digit
        outputPASS35 = sp.getoutput("grep 'dcredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'dcredit='")
    
    
        #provide at least one uppercase character
        outputPASS36 = sp.getoutput("grep 'ucredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'ucredit='")
    
        #provide at least one special character
        outputPASS37 = sp.getoutput("grep 'ocredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'ocredit='")
    
        #provide at least one lowercase character
        outputPASS37 = sp.getoutput("grep 'lcredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'lcredit='")
        
        
        print(CSELECTED + "\n[Control] 5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)")    
        outputPASS38 = sp.getoutput("grep -E '^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$' /etc/pam.d/password-auth /etc/pam.d/system-auth | cut -d '.' -f3")
        
        substring = "sha512"
        
        if substring in outputPASS38:
            print(CEND+"\033[1m" + "Status: "  + CGREEN + "[PASS] " + "\033[0m" + "5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)")
        else: 
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] "  + "\033[0m" + "5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)") 
    
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\n" + outputPASS38)   
    
    
    
        #5.5.1.1 Ensure password expiration is 365 days or less (Scored) 
        print(CSELECTED+"\n[Control] 5.5.1.1 Ensure password expiration is " + userIN1 + " days or less (Scored)")
        outputPASS29 = sp.getoutput("grep -oP '^PASS_MAX_DAYS\s+\K([0-9]+)' /etc/login.defs")
    
    
        if int(outputPASS29) <= int(userIN1):
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.1 Ensure password expiration is " + userIN1 + " days or less (Scored)")
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.1 Ensure password expiration is " + userIN1 +  " days or less (Scored)")
            #Remediation:
    
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_MAX_DAYS " + outputPASS29) 
    
    
    
        #5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - Site Policy 
        print(CSELECTED+"\n[Control] 5.5.1.2 Ensure minimum days between password changes is " + userIN2 + " or more (Scored) - Site Policy")
        outputPASS30 = sp.getoutput("grep -oP '^PASS_MIN_DAYS\s+\K([0-9]+)' /etc/login.defs")
    
        #Add option for user input
        if int(outputPASS30) >= int(userIN2):
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is "  + userIN2 +  " or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[0m")
            print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_MIN__DAYS " + outputPASS30)
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is " + userIN2 + " or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[0m")
            print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_MIN__DAYS " + outputPASS30)
            #Remediation:
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs: PASS_MIN_DAYS 7")
    
    
    
    
    
        #*****
        #5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - All Users 
        #*****  
        print(CSELECTED+"\n[Control] 5.5.1.2 Ensure minimum days between password changes is " + userIN3 + " or more (Scored) - All Users")
        outputPASS31 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow  | cut -d: -f4")
    
        for outputPASS31 in outputPASS31.split():
            try:
                if int(outputPASS31) < int(userIN3):
                    print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is "  + userIN3 +  " or more (Scored) - " + 
                          "\033[1m" + "All Users" + "\033[0m")
                    print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " \nPASS_MIN_DAYS: " + "\n" + outputPASS31)
                    print("\033[1m"+"[Remediation]"+"\033[0m")
                    print("Modify user parameters for all users with a password set to match: chage --mindays 7 <user>")                 
                    break
                else:
                    print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is "  + userIN3 + " or more (Scored) - " + 
                          "\033[1m" + "All Users" + "\033[0m")
                    print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " \nPASS_MIN_DAYS: " + "\n" + outputPASS31)                    
                    break
            except ValueError:
                pass   
    
        
    
    
    
    
    
        #*****
        #5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - Site Policy
        #*****
        print(CSELECTED + "\n[Control] 5.5.1.3 Ensure password expiration warning days is "  + userIN4 + " or more (Scored) - Site Policy")
        outputPASS32 = sp.getoutput("grep -oP '^PASS_WARN_AGE\s+\K([0-9]+)' /etc/login.defs")
    
        if int(outputPASS32) >= int(userIN4):
            print("\033[1m"+ CEND + "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is "  + userIN4 + " or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[1m")
            print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_WARN_AGE " + outputPASS32)   
        else:
            print("\033[1m" + CEND + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is "  + userIN4 +  " or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[1m")
            print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_WARN_AGE " + outputPASS32)   
            #Remediation:
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs: PASS_WARN_AGE 7")           
    
    
    
    
    
        print(CSELECTED + "\n[Control] 5.5.1.3 Ensure password expiration warning days is "  + userIN5 + " or more (Scored) - All Users")
    
        outputPASS33 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f6 | tr -d '\t'")
        outputPASS33c = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6")
    
        print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\nPASS_WARN_AGE: " + "\n" + outputPASS33c) 
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.3 Ensure password expiration warning days is "  + userIN5 + " or more (Scored) - All Users] " + "\033[0m") 
    
        for x in outputPASS33.split():
            if int(x) >= int(userIN5):
                print("Warning days: " + x + " [PASS]")
    
                print("\033[1m"+ "Status: " + CEND + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is "  + userIN5 +  " or more (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")                    
            else:
                print("\nWarning days: " + x + " [FAIL]")
                print("\033[1m" + "Status: " + CEND + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is "  + userIN5 + " or more (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")
                print("\033[1m"+"[Remediation]"+"\033[0m")
                print("Modify user parameters for all users with a password set to match: chage --warndays 7 <user>\n")
    
    
    
    
        #****
        #5.5.1.4 Ensure inactive password lock is 30 days or less (Scored)
        #****
        outputPASS34 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f7")
        outputPASS34c = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7")
    
        print(CSELECTED + "\n5.5.1.4 Ensure inactive password lock is " + userIN6 +  " days or less (Scored) - All Users")
    
        print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\n" + outputPASS34c) 
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.4 Ensure inactive password lock is "  + userIN6 + " days or less (Scored) - All Users] " + "\033[0m")     
    
        for y in outputPASS34.split():
            if int(y) <= int(userIN6):
                print("Warning days: " + y + " [PASS]")
    
                print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.4 Ensure inactive password lock is " + userIN6 +  " days or less (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")                    
            else:
                print("Warning days: " + y + " [FAIL]")
                print("\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.4 Ensure inactive password lock is " + userIN6 +  " days or less (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")
                print("\033[1m"+"[Remediation]"+"\033[0m")
                print("Modify user parameters for all users with a password set to match: chage --inactive 30 <user>\n")    
    
    
        #****
        #5.5.1.5 Ensure all users last password change date is in the past (Scored)
        #***
        print(CSELECTED+"\n5.5.1.5 Ensure all users last password change date is in the past (Scored) - All Users")    
    
        outputPASS35 = os.popen('sudo ./5.5.1.5.sh')
        #print(outputPASS35.read())
    
        standOutput = ''
        if not standOutput:
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.5 Ensure all users last password change date is in the past (Scored) - " + 
                  "\033[1m" + "All Users" + "\033[0m")  
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.5 Ensure all users last password change date is in the past (Scored) - " + 
                  "\033[1m" + "All Users" + "\033[0m")
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Investigate any users with a password change date in the future and correct them. " + 
                  "Locking the account, \nexpiring the password, or resetting the password manually may be appropriate.\n")       
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.5 Ensure all users last password change date is in the past (Scored) - All Users] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "NO OUTPUT"+outputPASS35.read()) 
        
        
    def a_a_a_Standard():
        print(result2)
        
        #5.2.3 Ensure permissions on SSH private host key files are configured (Scored)
        #Rationale - If an unauthorized user obtains the private SSH host key file, the host could be impersonated
    
        result3 = "\033[1m" + "\n[Result - Access, Authentication and Authorization]" + "\033[0m"
        print(result3)
    
        print(CSELECTED+"\n[Control] 5.2.3 Ensure permissions on SSH private host key files are configured (Scored)")
        print("\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.3 Ensure permissions on SSH private host key files are configured (Scored)")
        outputSSH523 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; | grep Gid")
        print(outputSSH523) 
    
    
        outputSSH524 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;");  
        outputSSH25 = sp.getoutput("sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;")    
    
    
        #5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
        print(CSELECTED+"[Control] 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
        outputSSH27 = sp.getoutput("sudo sshd -T | grep -oP '(?<=maxauthtries).*'")
    
        if int(outputSSH27) <= 4:
            print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
        else:
            print(CEND+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)")
    
    
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " MaxAuthTries" +outputSSH27)
    
    
        #5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
        print(CSELECTED+"[Control] 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        outputSSH28 = sp.getoutput("sudo sshd -T | grep -oP '(?<=ignorerhosts).*' ")
        #print(outputSSH28) 
    
        if outputSSH28 == " yes":
            print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        else:
            print(END+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)")
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " IgnoreRhosts" +outputSSH28)
        
        
        #5.4.1 Ensure password creation requirements are configured (Scored)
    
        print(CSELECTED + "\n[Control] 5.4.1 Ensure passsqword creation requirements are configured (Scored)")
        #provide at least one digit
        outputPASS35 = sp.getoutput("grep 'dcredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'dcredit='")
    
        #provide at least one uppercase character
        outputPASS36 = sp.getoutput("grep 'ucredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'ucredit='")
    
        #provide at least one special character
        outputPASS37 = sp.getoutput("grep 'ocredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'ocredit='")
    
        #provide at least one lowercase character
        outputPASS37 = sp.getoutput("grep 'lcredit'  /etc/security/pwquality.conf | cut -d '#' -f2 | tr -d 'lcredit='")
    
    
        print(outputPASS35)
        print(outputPASS36)
        print(outputPASS37)
        print(outputPASS37)
        
    
        
        
        print(CSELECTED + "\n[Control] 5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)")    
        outputPASS38 = sp.getoutput("grep -E '^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$' /etc/pam.d/password-auth /etc/pam.d/system-auth | cut -d '.' -f3")
        
        substring = "sha512"
        
        if substring in outputPASS38:
            print(CEND+"\033[1m" + "Status: "  + CGREEN + "[PASS] " + "\033[0m" + "5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)")
        else: 
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] "  + "\033[0m" + "5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)") 
    
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.4.4 Ensure password hashing algorithm is SHA-512 (Scored)] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\n" + outputPASS38)   
    
    
        
        
    
    
        #5.5.1.1 Ensure password expiration is 365 days or less (Scored)
        print(CSELECTED+"5.5.1.1 Ensure password expiration is 365 days or less (Scored)")
        outputPASS29 = sp.getoutput("grep -oP '^PASS_MAX_DAYS\s+\K([0-9]+)' /etc/login.defs")
    
        if int(outputPASS29) <= 365:
            print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.1 Ensure password expiration is 365 days or less (Scored)")
        else:
            print(CEND+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.1 Ensure password expiration is 365 days or less (Scored)")
            #Remediation:
          
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_MAX_DAYS " + outputPASS29) 
        
        
        
        #5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - Site Policy
        print(CSELECTED+"[Control] 5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - Site Policy")
        outputPASS30 = sp.getoutput("grep -oP '^PASS_MIN_DAYS\s+\K([0-9]+)' /etc/login.defs")
    
        #Add option for user input
        if int(outputPASS30) >= 7:
            print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[0m")
        else:
            print(CEND+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[0m")
            #Remediation:
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs: PASS_MIN_DAYS 7")
           
                
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_MIN__DAYS " + outputPASS30) 
        
        
        #*****
        #5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - All Users 
        #*****  
        print(CSELECTED+"[Control] 5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - All Users")
        outputPASS31 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow  | cut -d: -f4")
            
        for outputPASS31 in outputPASS31.split():
            try:
                if int(outputPASS31) < 7:
                    print(CEND+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")
                    print("\033[1m"+"[Remediation]"+"\033[0m")
                    print("Modify user parameters for all users with a password set to match: chage --mindays 7 <user>")                 
                    break
                else:
                    print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored) - " + 
                              "\033[1m" + "All Users" + "\033[0m")                    
                    break
            except ValueError:
                pass   
            
        #print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " \nPASS_MIN_DAYS: " + "\n" + outputSSH31)
            
           
                
      
        
        #*****
        #5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - Site Policy
        #*****
        print(CSELECTED+"[Control] 5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - Site Policy")
        outputPASS32 = sp.getoutput("grep -oP '^PASS_WARN_AGE\s+\K([0-9]+)' /etc/login.defs")
    
        if int(outputPASS32) >= 7:
            print(CEND+"\033[1m"+ "\nStatus: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[1m")
        else:
            print(CEND+"\033[1m" + "\nStatus: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - " + "\033[1m" + "Site Policy" + "\033[1m")
            #Remediation:
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs: PASS_WARN_AGE 7")           
          
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION]" + "\033[0m" + " PASS_WARN_AGE " + outputPASS32)    
        
    
        print(CSELECTED+"\n[Control] 5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - All Users")
        outputPASS33 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f6 | tr -d '\t'")
        outputPASS33c = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6")
    
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\nPASS_WARN_AGE: " + "\n" + outputPASS33c) 
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - All Users] " + "\033[0m") 
    
        for x in outputPASS33.split():
            if int(x) >= 7:
                print("Warning days: " + x + " [PASS]")
                
                print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - " + 
                              "\033[1m" + "All Users" + "\033[0m")                    
            else:
                print("\nWarning days: " + x + " [FAIL]")
                print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.3 Ensure password expiration warning days is 7 or more (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")
                print("\033[1m"+"[Remediation]"+"\033[0m")
                print("Modify user parameters for all users with a password set to match: chage --warndays 7 <user>\n")
                
            
        
    
        #****
        #5.5.1.4 Ensure inactive password lock is 30 days or less (Scored)
        #****
        print(CSELECTED+"[Control] 5.5.1.4 Ensure inactive password lock is 30 days or less (Scored)")
        outputPASS34 = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f7")
        outputPASS34c = sp.getoutput("sudo grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7")
           
        print(CEND+"\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "\n" + outputPASS34c) 
    
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.4 Ensure inactive password lock is 30 days or less (Scored) - All Users] " + "\033[0m")     
        
        for y in outputPASS34.split():
            if int(y) <= 30:
                print("Warning days: " + y + " [PASS]")
                
                print(END+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.4 Ensure inactive password lock is 30 days or less (Scored) - " + 
                              "\033[1m" + "All Users" + "\033[0m")                    
            else:
                print("Warning days: " + y + " [FAIL]")
                print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.4 Ensure inactive password lock is 30 days or less (Scored) - " + 
                      "\033[1m" + "All Users" + "\033[0m")
                print("\033[1m"+"[Remediation]"+"\033[0m")
                print("Modify user parameters for all users with a password set to match: chage --inactive 30 <user>\n")    
        
        
        #****
        #5.5.1.5 Ensure all users last password change date is in the past (Scored)
        #***
        print(CSELECTED+"\n[Control] 5.5.1.5 Ensure all users last password change date is in the past (Scored) - All Users")    
      
        outputPASS35 = os.popen('sudo ./5.5.1.5.sh')
        #print(outputPASS35.read())
        
        standOutput = ''
        if not standOutput:
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "5.5.1.5 Ensure all users last password change date is in the past (Scored) - " + 
                              "\033[1m" + "All Users" + "\033[0m")  
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "5.5.1.5 Ensure all users last password change date is in the past (Scored) - " + 
                  "\033[1m" + "All Users" + "\033[0m")
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("Investigate any users with a password change date in the future and correct them. " + 
            "Locking the account, \nexpiring the password, or resetting the password manually may be appropriate.\n")       
       
        print("\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 5.5.1.5 Ensure all users last password change date is in the past (Scored) - All Users] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "NO OUTPUT"+outputPASS35.read()) 
        
    
    
    
    def system_main():
        #6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
        print(result2)
    
        print(CSELECTED+"\n[Control]6.1.2 Ensure permissions on /etc/passwd are configured (Scored)")
        outputRSM1 = sp.getoutput("stat /etc/passwd")
    
        #Access
        outputSM1 = sp.getoutput("stat /etc/passwd | grep 'Access: (0' | cut -d ':' -f2 | cut -d '/' -f1 |  tr -d '(0'")
    
        #Uid
        outputSM2 = sp.getoutput("stat /etc/passwd | grep 'Access: (' | cut -d ':' -f3 | tr -d '(/root) Gid'")
    
        #Gid
        outputSM3 = sp.getoutput("stat /etc/passwd | grep 'Access: (' | cut -d ':' -f4 | tr -d '(/root)'")
    
        if outputSM1.strip() == "644" and int(outputSM2) == 0 and int(outputSM3) == 0:
            print(CEND+"\033[1m"+ "Status: " + CGREEN + "[PASS] " + "\033[0m" + "6.1.2 Ensure permissions on /etc/passwd are configured (Scored)")  
        else:
            print(CEND+"\033[1m" + "Status: " + CRED2 + CBLINK + "[FAIL] " + "\033[0m" + "6.1.2 Ensure permissions on /etc/passwd are configured (Scored)" )
            print("\033[1m"+"[Remediation]"+"\033[0m")
            print("chown root:root /etc/passwd")
            print("chmod 644 /etc/passwd")
    
        print(CEND+"\033[1m"+ "\nAdditional Information: " + CBLUE + "[INFO - 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)] " + "\033[0m" )   
        print("\033[1m"+ "Current configuration: " + CORANGE + "[CONFIRMATION] " + "\033[0m" + "NO OUTPUT" + outputRSM1 )   
        
        
        
    
    
    def vulnerabilities_scan():
        #print ("Running vulnerabilities scan....")
        while True:
            try:
                option = input("\033[1m"+"\n[Audit Scan Option:]"+"\033[0m"+"\n\nPlease enter the following option:\n\n"
                               "1  -  Initial Setup\n"
                               "2  -  Services\n"
                               "3  -  Network Configuration\n"
                               "4  -  Logging and Auditing\n"
                               "5  -  Access, Authentication and Authorization\n"
                               "6  -  System Maintenance\n" 
                               "7  -  Full Scan\n"        
                               "q  -  Quit"
                               "\nEnter a option: ")     
            except ValueError:
                print("Sorry, I didn't understand that.")
                continue
            if  option == 'q':
                print("Program exited successfully")
                exit()
            elif int(option) == 1:
                #Initial Setup
                print("Running scan...")	
                time.sleep(3)                        
                initial_setup_scan()
    
    
            elif int(option) == 2:
                #Services
                print("Running scan...")	
                time.sleep(3)            
                service_scan()
    
    
            elif int(option) == 3:
                #Network Configuration
                print("Running scan...")	
                time.sleep(3)            
                network_configuration_scan()
    
            elif int(option) == 4:
                #Logging and Auditing
                print("Running scan...")	
                time.sleep(3)     
                logging_auditing()
    
    
            elif int(option) == 5:
                #Access, Authentication and Authorization            
                while True:
                    try:
                        option = input("\033[1m"+"\n[Audit Scan Option:]"+"\033[0m"+"\n\nPlease enter the following option:\n\n"
                                       "1  -  Basic Scan\n"
                                       "2  -  Custom Scan\n"     
                                       "q  -  Quit"
                                       "\nEnter a option: ") 
                    except ValueError:
                        print("Sorry, I didn't understand that.")
                        continue                    
                    if  option == 'q':
                        print("Program exited successfully")
                        exit()                
                    elif int(option) == 1:
                        a_a_a_Standard()
                    elif int(option) == 2:
                        a_a_a_C()
                        print("Running scan...")	
                        time.sleep(3)                      
            
                    elif int(option) < 0:
                        print("Sorry, your input cannot be negative.")
                        continue
                    else:
                        print("Sorry, your input must be a valid option stated above.")                       
    
    
            elif int(option) == 6:
                #System Maintenance
                print("Running scan...")	            
                time.sleep(3)            
                system_main()
    
    
            elif int(option) == 7:
                #Full Scan
                break
    
    
            elif int(option) < 0:
                print("Sorry, your input cannot be negative.")
                continue
            else:
                print("Sorry, your input must be a valid option stated above.")         
    
    
    
    def report_comparision():
        print("Running report comparison...")
    
    def report_view():
        print("Running report...")
    
    
    def main():
    
    
        while True:
            try:
                p = input("[Welcome to IT Audit Baseline Analyzer] \n\nPlease enter the following option:\n\n"
                          "1 - View CIS CentOS Linux 8 Benchmark\n"
                          "2 - Audit scan\n"
                          "3 - Report comparision\n"
                          "4 - View report\n"
                          "5 - Quit"
                          "\nEnter a option: ")
            except ValueError:
                print("Sorry, I didn't understand that.")
                continue
            if  int(p) < 0:
                print("Sorry, your response must not be negative.")
                continue 
            elif int(p) == 1:
                centOS_cis_benchmarks()
                break
            elif int(p) == 2:
                print("\n") 
                vulnerabilities_scan() 		
                break
            elif int(p) == 3:
                report_comparision()
                break
            elif int(p) == 4:
                report_view()
                break
            elif int(p) == 5:
                print ("Program exited successfully.")
                exit()        
            else:
                print("Sorry, your input must be a valid option stated above.")              
    main()    
    

def bigmain():
    while True:
        try:
            option = input("Please select an option:\n\n"
                                "1 - Windows\n"
                                 "2 - Ubuntu\n"
                                 "3 - CentoS\n"
                                 "q - Quit\n"
                                 "\nEnter option: ")
        except ValueError:
            print("Invalid input")

        if option == 'q':
            print("Program exited")
            exit()

        elif int(option) == 1:
            windows()
            bigmain()

            break

        elif int(option) == 2:
            ubuntu()
            bigmain()

            break

        elif int(option) == 3:
            centos()
            bigmain()

            break

bigmain()

"""
        print(p_output)
        print(p_list)
        print(p_list[0])
        print(p_dict)
"""