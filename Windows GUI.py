import tkinter as tk
from tkinter import ttk
from tkinter.ttk import *
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
import shutil

from tkinter import *

# ==== Vars ====
basicRes = []
log = []
target = 'localhost'


def adirectory():
    import time
    import configparser
    config = configparser.ConfigParser()
    time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    timestr = time + " Windows Settings.ini"
    
    def complexity():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select ComplexityEnabled', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("-----------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['complexity'] = p_dict
        
    def maxpassage():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select MaxPasswordAge', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("--------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['maxpage'] = p_dict

    def minpassage():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select MinPasswordAge', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("--------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['minpage'] = p_dict
    
    def minplength():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select MinPasswordLength', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("-----------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['minplength'] = p_dict
    
    def phistorycount():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select PasswordHistoryCount', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("--------------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['phistorycount'] = p_dict            
        
    def reverseencrypt():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select ReversibleEncryptionEnabled', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("---------------------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['reverseencrypt'] = p_dict 
    
    def lockoutduration():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select LockoutDuration', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("---------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['lockouttime'] = p_dict
    
    def lockoutobserve():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select LockoutObservationWindow', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("------------------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['lockoutobservetime'] = p_dict
    
    def lockoutcount():
        p = sp.Popen('powershell.exe Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold', stdout=sp.PIPE)
        p_output = p.communicate()[0].decode()
        p_output = p_output.replace("\r\n", "")
        p_output = p_output.replace(" ", "")
        p_list = p_output.replace("----------------", "=")
        p_list = p_list.split("=")
        
        p_dict = dict([p_list])
        config['lockoutthreshold'] = p_dict         
        
    complexity()
    maxpassage()
    minpassage()
    minplength()
    phistorycount()
    reverseencrypt()
    lockoutduration()
    lockoutobserve()
    lockoutcount()
    
    with open(timestr,'w') as configfile:
        config.write(configfile)
        
    config.read(timestr)
    count = 0
    count2 = 0
    print("\n")
    print("==============================================================")
    print("\n")
    print("Password and Lockout settings \n")
    if(config['complexity']['ComplexityEnabled'] == "True"):
        Stat1 = "No need to change Password setting: ComplexityEnabled \n"
        count = count + 1
    
    else:
        Stat1 = "Setting 'ComplexityEnabled' requires change: False to True \n"
        count2 = count2 + 1
    
    if(config['maxpage']['MaxPasswordAge'] == "42.00:00:00"):
        Stat2 = "No need to change Password setting: Maximum Password Age \n"
        count = count + 1
    
    else:
        Stat2 = "Setting 'MaxPasswordAge' requires change: Set value to equal to or more than 42.00 \n"
        count2 = count2 + 1
        
    if(config['minpage']['MinPasswordAge'] == "1.00:00:00"):
        Stat3 = "No need to change Password setting: Minimum Password Age \n"
        count = count + 1
    
    else:
        Stat3 = "Setting 'MinPasswordAge' requires change: Set value to equal to or more than 1.00 \n"
        count2 = count2 + 1
        
    if(int(config['minplength']['MinPasswordLength']) >= 14):
        Stat4 = "No need to change Password setting: MinPasswordLength \n"
        count = count + 1
        
    else:
        Stat4 = "Setting 'MinPasswordLength' requires change: Set value to equal to or more than 14 \n"
        count2 = count2 + 1
            
    if(int(config['phistorycount']['PasswordHistoryCount']) >= 24):
        Stat5 = "No need to change Password setting: PasswordHistoryCount \n"
        count = count + 1
            
    else:
        Stat5 = "Setting 'PasswordHistoryCount' requires change: Set value to equal to or more than 24 \n"
        count2 = count2 + 1
                
    if(config['reverseencrypt']['ReversibleEncryptionEnabled'] == "False"):
        Stat6 = "No need to change Password setting: ReversibleEncryptionEnabled \n"
        count = count + 1
                
    else:
        Stat6 = "Setting 'ReversibleEncryptionEnabled' requires change: True to False \n"
        count2 = count2 + 1
                    
    if(config['lockouttime']['LockoutDuration'] == "00:30:00"):
        Stat7 = "No need to change Password setting: LockoutDuration \n"
        count = count + 1
                    
    else:
        Stat7 = "Setting 'LockoutDuration' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                        
    if(config['lockoutobservetime']['LockoutObservationWindow'] == "00:30:00"):
        Stat8 = "No need to change Password setting: LockoutObservationWindow \n"
        count = count + 1
                        
    else:
        Stat8 = "Setting 'LockoutObservationWindow' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                            
    if(int(config['lockoutthreshold']['LockoutThreshold']) <= 10 and int(config['lockoutthreshold']['LockoutThreshold']) != 0 ):
        Stat9 = "No need to change Password setting: LockoutThreshold \n"
        count = count + 1
                            
    else:
        Stat9 = "Setting 'LockoutThreshold' requires change: Set value to 10 or fewer invalid logon attempts but not 0 \n"
        count2 = count2 + 1
                                
    #if(config['complexity']['ComplexityEnabled'] == "True"):
        #print("No need to change Password setting: ComplexityEnabled \n")
                                
    #else:
        #print("Setting 'ComplexityEnabled' requires change: False to True \n")                                    
        
    #print(config.sections())
    print("\n")
    print("============================================================== \n")     
    

    listbox.insert(0, "Writing to " + timestr + " on desktop.")
    listbox.insert(1, " ")
    listbox.insert(2, "Password Security + Remediations")
    listbox.insert(3, " ")
    listbox.insert(4, Stat1)
    listbox.insert(4, Stat2)
    listbox.insert(4, Stat3)
    listbox.insert(4, Stat4)
    listbox.insert(4, Stat5)
    listbox.insert(4, Stat6)
    listbox.insert(4, Stat7)
    listbox.insert(4, Stat8)
    listbox.insert(4, Stat9)
    
    listbox2.insert(0, " ")
    listbox2.insert(1, "Number of Compliant settings")
    listbox2.insert(3, "- " + str(count))
    listbox2.insert(4, " ")
    listbox2.insert(5, "Number of Non-Compliant settings")
    listbox2.insert(6, "- " + str(count2))
    

def startScan_Intermediate():
    print("")
    

def startScan_Advanced():
    print("")    
    
def saveScan():
    date = datetime.now().strftime("%Y_%m_%d-%H:%M:%S_%p")    

    
    
# ==== GUI ====
gui = Tk()
gui.title('IT Risk Audit Baseline Analyzer')
gui.geometry("720x500+20+20")

# ==== Colors ====
m1c = '#00ee00'
bgc = '#222222'
dbg = '#000000'
fgc = '#111111'

gui.tk_setPalette(background="lightgrey", foreground="Black", activeBackground="white",activeForeground="black", highlightColor="White", highlightBackground="Black")

# ==== Labels ====
L11 = Label(gui, text = "Windows Audit",  font=("Helvetica", 16, 'underline', 'bold'))
L11.place(x = 16, y = 10)

L26 = Label(gui, text = "Results: ")
L26.place(x = 16, y = 60)
L27 = Label(gui, text = "[ ... ]")
L27.place(x = 180, y = 60)


# ==== Buttons / Scans ====
L26 = Label(gui, text = "Scan Options: ", font=("Helvetica", 16, 'underline', 'bold'))
L26.place(x = 16, y = 220)
B11 = Button(gui, text = "Basic Scan", command=adirectory, bg='grey', fg='white')
B11.place(x = 16, y = 260, width = 170)

B12 = Button(gui, text = "Intermediate Scan", command=startScan_Intermediate, bg='grey', fg='white')
B12.place(x = 16, y = 310, width = 170)

B13 = Button(gui, text = "Advanced Scan", command=startScan_Advanced, bg='grey', fg='white')
B13.place(x = 16, y = 360, width = 170)

B21 = Button(gui, text = "Save Result", command=saveScan, bg='grey', fg='white')
B21.place(x = 200, y = 260, width = 200, height=130)


# ==== Result list ====
frame = Frame(gui)
frame.place(x = 10, y = 100, width = 680, height = 100)
listbox = Listbox(frame, width = 100, height = 6)
listbox.place(x = 0, y = 0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

frame = Frame(gui)
frame.place(x = 430, y = 270, width = 260, height = 100)
listbox2 = Listbox(frame, width = 100, height = 6)
listbox2.place(x = 0, y = 0)
listbox2.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox2.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox2.yview)

# ==== Start GUI ====
gui.mainloop()
