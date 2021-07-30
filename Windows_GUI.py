import tkinter as tk
from tkinter import ttk
from tkinter.ttk import *
import pyfiglet
import fileinput
import time
from parse import *
import winrm

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


def basic():
    host = IP.get()
    domain = Domain.get()
    user = username.get()
    password = passwd.get()
    
    session = winrm.Session(host, auth=('{}@{}' .format(user ,domain), password), transport='ntlm') 
    
    import time
    import configparser
    config = configparser.ConfigParser()
    time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    timestr = time + " Basic Windows Settings.ini"
    
    def complexity():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['complexity'] = p_dict
        
    def maxpassage():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MaxPasswordAge')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['maxpage'] = p_dict

    def minpassage():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordAge')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['minpage'] = p_dict
    
    def minplength():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['minplength'] = p_dict
    
    def phistorycount():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordHistoryCount')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['phistorycount'] = p_dict            
        
    def reverseencrypt():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object ReversibleEncryptionEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['reverseencrypt'] = p_dict 
    
    def lockoutduration():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockouttime'] = p_dict
    
    def lockoutobserve():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutObservationWindow')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockoutobservetime'] = p_dict
    
    def lockoutcount():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockoutthreshold'] = p_dict 
              
    def limitpass():
        p = session.run_ps('Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "LimitBlankPasswordUse" | Select-Object LimitBlankPasswordUse')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['limitpass'] = p_dict
    
    def crashonaudit():
        p = session.run_ps('Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "CrashOnAuditFail" | Select-Object CrashOnAuditFail')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['crashonaudit'] = p_dict
        
    def disablecad():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "DisableCAD" | Select-Object DisableCAD')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disablecad'] = p_dict
    
    def nousername():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "DontDisplayLastUserName" | Select-Object DontDisplayLastUserName')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['nousername'] = p_dict
    
    def legaltext():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "LegalNoticeText" | Select-Object LegalNoticeText')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("\x00", "")
        p_output = p_output.replace("---------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['legaltext'] = p_dict    
        
    def legalcaption():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "LegalNoticeCaption" | Select-Object LegalNoticeCaption')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['legalcaption'] = p_dict          

        
    def securitysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "RequireSecuritySignature" | Select-Object RequireSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")    
        
        p_dict = dict([p_list])
        config['securitysig'] = p_dict
        
    def enablesecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "EnableSecuritySignature" | Select-Object EnableSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['enablesecuritysig'] = p_dict
        
    def enableplainpass():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "EnablePlainTextPassword" | Select-Object EnablePlainTextPassword')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")  
        
        p_dict = dict([p_list])
        config['enablesplainpass'] = p_dict
        
    def serverautodisconnect():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "AutoDisconnect" | Select-Object AutoDisconnect')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")   
        
        p_dict = dict([p_list])
        config['serverautodisconnect'] = p_dict
    
    def serversecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "RequireSecuritySignature" | Select-Object RequireSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")  
        
        p_dict = dict([p_list])
        config['serversecuritysig'] = p_dict
        
    def serverenablesecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "EnableSecuritySignature" | Select-Object EnableSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")   
        
        p_dict = dict([p_list])
        config['serverenablesecuritysig'] = p_dict
        
    def serverenableforcelogoff():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "enableforcedlogoff" | Select-Object enableforcedlogoff')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['serverenableforcelogoff'] = p_dict
    
    complexity()
    maxpassage()
    minpassage()
    minplength()
    phistorycount()
    reverseencrypt()
    lockoutduration()
    lockoutobserve()
    lockoutcount()
    limitpass()
    crashonaudit()
    disablecad()
    nousername()
    legaltext()
    legalcaption()
    securitysig()
    enablesecuritysig()
    enableplainpass()
    serverautodisconnect()
    serversecuritysig()
    serverenablesecuritysig()
    serverenableforcelogoff()
    
    with open(timestr,'w') as configfile:
        config.write(configfile)
        
    config.read(timestr)
    count = 0
    count2 = 0
    print("\n")
    print("==============================================================")
    print("\n")
    print("Windows Controls \n")
    if(config['complexity']['ComplexityEnabled'] == "True"):
        Stat1 = "No need to change Control: ComplexityEnabled \n"
        count = count + 1
    
    else:
        Stat1 = "Setting 'ComplexityEnabled' requires change: False to True \n"
        count2 = count2 + 1
    
    if(config['maxpage']['MaxPasswordAge'] == "42.00:00:00"):
        Stat2 = "No need to change Control: Maximum Password Age \n"
        count = count + 1
    
    else:
        Stat2 = "Setting 'MaxPasswordAge' requires change: Set value to equal to or more than 42.00 \n"
        count2 = count2 + 1
        
    if(config['minpage']['MinPasswordAge'] == "1.00:00:00"):
        Stat3 = "No need to change Control: Minimum Password Age \n"
        count = count + 1
    
    else:
        Stat3 = "Setting 'MinPasswordAge' requires change: Set value to equal to or more than 1.00 \n"
        count2 = count2 + 1
        
    if(int(config['minplength']['MinPasswordLength']) >= 14):
        Stat4 = "No need to change Control: MinPasswordLength \n"
        count = count + 1
        
    else:
        Stat4 = "Setting 'MinPasswordLength' requires change: Set value to equal to or more than 14 \n"
        count2 = count2 + 1
            
    if(int(config['phistorycount']['PasswordHistoryCount']) >= 24):
        Stat5 = "No need to change Control: PasswordHistoryCount \n"
        count = count + 1
            
    else:
        Stat5 = "Setting 'PasswordHistoryCount' requires change: Set value to equal to or more than 24 \n"
        count2 = count2 + 1
                
    if(config['reverseencrypt']['ReversibleEncryptionEnabled'] == "False"):
        Stat6 = "No need to change Control: ReversibleEncryptionEnabled \n"
        count = count + 1
                
    else:
        Stat6 = "Setting 'ReversibleEncryptionEnabled' requires change: True to False \n"
        count2 = count2 + 1
                    
    if(config['lockouttime']['LockoutDuration'] == "00:30:00"):
        Stat7 = "No need to change Control: LockoutDuration \n"
        count = count + 1
                    
    else:
        Stat7 = "Setting 'LockoutDuration' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                        
    if(config['lockoutobservetime']['LockoutObservationWindow'] == "00:30:00"):
        Stat8 = "No need to change Control: LockoutObservationWindow \n"
        count = count + 1
                        
    else:
        Stat8 = "Setting 'LockoutObservationWindow' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                            
    if(int(config['lockoutthreshold']['LockoutThreshold']) <= 10 and int(config['lockoutthreshold']['LockoutThreshold']) != 0 ):
        Stat9 = "No need to change Control: LockoutThreshold \n"
        count = count + 1
                            
    else:
        Stat9 = "Setting 'LockoutThreshold' requires change: Set value to 10 or fewer invalid logon attempts but not 0 \n"
        count2 = count2 + 1
                                
    if(int(config['limitpass']['limitblankpassworduse']) == 1):
        Stat10 = "No need to change Control: LimitBlankPasswordUse \n"
        count = count + 1
                            
    else:
        Stat10 = "Setting 'LimitBlankPasswordUse' requires change: Set value to 1 OR Enable in Accounts: Limit local account use of blank passwords to console logon only in GPO \n"
        count2 = count2 + 1
    
    if(int(config['crashonaudit']['crashonauditfail']) == 0):
        Stat11 = "No need to change Control: CrashOnAuditFail \n"
        count = count + 1
                                
    else:
        Stat11 = "Setting 'CrashOnAuditFail' requires change: Set value to 0 OR Ensure in Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['disablecad']['disablecad']) == 0):
        Stat12 = "No need to change Control: DisableCAD \n"
        count = count + 1
                                    
    else:
        Stat12 = "Setting 'DisableCAD' requires change: Set value to 0 OR Ensure in 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['nousername']['dontdisplaylastusername']) == 1):
        Stat13 = "No need to change Control: DontDisplayLastUserName \n"
        count = count + 1
                                        
    else:
        Stat13 = "Setting 'DontDisplayLastUserName' requires change: Set value to 1 OR Ensure in 'Interactive logon: Don't display last signed-in' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1
        
    if(config['legaltext']['legalnoticetext'] != "\x00" ):
        Stat14 = "No need to change Control: LegalNoticeText \n"
        count = count + 1
                                            
    else:
        Stat14 = "Setting 'LegalNoticeText' requires change: Configure 'Interactive logon: Message text for users attempting to log on' in GPO \n"
        count2 = count2 + 1 
        
    if(config['legalcaption']['legalnoticecaption'] != "" ):
        Stat15 = "No need to change Control: LegalNoticeCaption \n"
        count = count + 1
                                                
    else:
        Stat15 = "Setting 'LegalNoticeCaption' requires change: Configure 'Interactive logon: Message title for users attempting to log on' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['securitysig']['requiresecuritysignature']) == 1 ):
        Stat16 = "No need to change Control: RequireSecuritySignature \n"
        count = count + 1
                                                    
    else:
        Stat16 = "Setting 'RequireSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['enablesecuritysig']['enablesecuritysignature']) == 1 ):
        Stat17 = "No need to change Control: EnableSecuritySignature \n"
        count = count + 1
                                                        
    else:
        Stat17 = "Setting 'EnableSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['enablesplainpass']['enableplaintextpassword']) == 0 ):
        Stat18 = "No need to change Control: EnablePlainTextPassword \n"
        count = count + 1
                                                            
    else:
        Stat18 = "Setting 'EnablePlainTextPassword' requires change: Set value to 0 OR Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1  
        
    if(int(config['serverautodisconnect']['autodisconnect']) <= 15 ):
        Stat19 = "No need to change Control: Server AutoDisconnect \n"
        count = count + 1
                                                                
    else:
        Stat19 = "Setting 'Server AutoDisconnect' requires change: Set value to fewer or lesser than 15 OR Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['serversecuritysig']['requiresecuritysignature']) == 1 ):
        Stat20 = "No need to change Control: Server RequireSecuritySignature \n"
        count = count + 1
                                                                    
    else:
        Stat20 = "Setting 'Server RequireSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['serverenablesecuritysig']['enablesecuritysignature']) == 1 ):
        Stat21 = "No need to change Control: Server EnableSecuritySignature \n"
        count = count + 1
                                                                        
    else:
        Stat21 = "Setting 'Server EnableSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['serverenableforcelogoff']['enableforcedlogoff']) == 1 ):
        Stat22 = "No need to change Control: Server enableforcedlogoff \n"
        count = count + 1
                                                                            
    else:
        Stat22 = "Setting 'Server enableforcedlogoff' requires change: Set value to 1 OR Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1    
        
    #print(config.sections())
    print("\n")
    print("============================================================== \n")     
    

    listbox.insert(0, "Writing to " + timestr + " in program folder.")
    listbox.insert(1, " ")
    listbox.insert(2, "Account Security + Remediations")
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
    listbox.insert(4, Stat10)
    listbox.insert(4, Stat11)
    listbox.insert(4, Stat12)
    listbox.insert(4, Stat13)
    listbox.insert(4, Stat14)
    listbox.insert(4, Stat15)
    listbox.insert(4, Stat16)
    listbox.insert(4, Stat17)
    listbox.insert(4, Stat18)
    listbox.insert(4, Stat19)
    listbox.insert(4, Stat20)
    listbox.insert(4, Stat21)
    listbox.insert(4, Stat22)
    
    
    listbox2.insert(0, "\nNumber of Compliant controls") 
    listbox2.insert(1, "--> " + str(count)) 
    listbox2.insert(2, "Number of Non-Compliant controls") 
    listbox2.insert(3, "--> " + str(count2)) 

    

def startScan_Intermediate():
    host = IP.get()
    domain = Domain.get()
    user = username.get()
    password = passwd.get()
    
    session = winrm.Session(host, auth=('{}@{}' .format(user ,domain), password), transport='ntlm')
    
    import time
    import configparser
    config = configparser.ConfigParser()
    time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    timestr = time + " Intermediate Windows Settings.ini"
    
    def complexity():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['complexity'] = p_dict
        
    def maxpassage():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MaxPasswordAge')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['maxpage'] = p_dict

    def minpassage():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordAge')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['minpage'] = p_dict
    
    def minplength():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['minplength'] = p_dict
    
    def phistorycount():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordHistoryCount')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['phistorycount'] = p_dict            
        
    def reverseencrypt():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object ReversibleEncryptionEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['reverseencrypt'] = p_dict 
    
    def lockoutduration():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockouttime'] = p_dict
    
    def lockoutobserve():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutObservationWindow')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockoutobservetime'] = p_dict
    
    def lockoutcount():
        p = session.run_ps('Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lockoutthreshold'] = p_dict 
              
    def limitpass():
        p = session.run_ps('Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "LimitBlankPasswordUse" | Select-Object LimitBlankPasswordUse')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['limitpass'] = p_dict
    
    def crashonaudit():
        p = session.run_ps('Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "CrashOnAuditFail" | Select-Object CrashOnAuditFail')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['crashonaudit'] = p_dict
        
    def disablecad():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "DisableCAD" | Select-Object DisableCAD')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disablecad'] = p_dict
    
    def nousername():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "DontDisplayLastUserName" | Select-Object DontDisplayLastUserName')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['nousername'] = p_dict
    
    def legaltext():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "LegalNoticeText" | Select-Object LegalNoticeText')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['legaltext'] = p_dict    
        
    def legalcaption():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "LegalNoticeCaption" | Select-Object LegalNoticeCaption')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['legalcaption'] = p_dict          

        
    def securitysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "RequireSecuritySignature" | Select-Object RequireSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")    
        
        p_dict = dict([p_list])
        config['securitysig'] = p_dict
        
    def enablesecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "EnableSecuritySignature" | Select-Object EnableSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['enablesecuritysig'] = p_dict
        
    def enableplainpass():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "EnablePlainTextPassword" | Select-Object EnablePlainTextPassword')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")  
        
        p_dict = dict([p_list])
        config['enablesplainpass'] = p_dict
        
    def serverautodisconnect():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "AutoDisconnect" | Select-Object AutoDisconnect')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")   
        
        p_dict = dict([p_list])
        config['serverautodisconnect'] = p_dict
    
    def serversecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "RequireSecuritySignature" | Select-Object RequireSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")  
        
        p_dict = dict([p_list])
        config['serversecuritysig'] = p_dict
        
    def serverenablesecuritysig():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "EnableSecuritySignature" | Select-Object EnableSecuritySignature')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")   
        
        p_dict = dict([p_list])
        config['serverenablesecuritysig'] = p_dict
        
    def serverenableforcelogoff():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "enableforcedlogoff" | Select-Object enableforcedlogoff')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['serverenableforcelogoff'] = p_dict
        
    def screensaveractive():
        p = session.run_ps('Get-Wmiobject win32_desktop | where name -match $env:USERNAME | Select-Object ScreenSaveActive')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['screensaveractive'] = p_dict 
        
    def screensaversecure():
        p = session.run_ps('Get-Wmiobject win32_desktop | where name -match $env:USERNAME | Select-Object ScreenSaverIsSecure')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['screensaversecure'] = p_dict
        
    def screensavertimeout():
        p = session.run_ps('Get-Wmiobject win32_desktop | where name -match $env:USERNAME | Select-Object ScreenSaverTimeout')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['screensavertimeout'] = p_dict
        
    def anonymousno():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Lsa -Name "RestrictAnonymous" | Select-Object RestrictAnonymous')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['anonymousno'] = p_dict 
        
    def disabledcreds():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Lsa -Name "DisableDomainCreds" | Select-Object DisableDomainCreds')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disabledcreds'] = p_dict
        
    def includeanon():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Lsa -Name "EveryoneIncludesAnonymous" | Select-Object EveryoneIncludesAnonymous')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['includeanon'] = p_dict 
        
    def restrictnull():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "RestrictNullSessAccess" | Select-Object RestrictNullSessAccess')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['restrictnull'] = p_dict
        
    def forceguest():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Lsa -Name "ForceGuest" | Select-Object ForceGuest')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['forceguest'] = p_dict 
        
    def nolmhash():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Control\Lsa -Name "NoLMHash" | Select-Object NoLMHash')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['nolmhash'] = p_dict  
        
    def ldapintergrity():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LDAP -Name "LDAPClientIntegrity" | Select-Object LDAPClientIntegrity')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ldapintergrity'] = p_dict    
        
    def behavioradmin():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "ConsentPromptBehaviorAdmin" | Select-Object ConsentPromptBehaviorAdmin')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['behavioradmin'] = p_dict
        
    def behavioruser():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "ConsentPromptBehaviorUser" | Select-Object ConsentPromptBehaviorUser')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['behavioruser'] = p_dict
        
    def installdetect():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableInstallerDetection" | Select-Object EnableInstallerDetection')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['installdetect'] = p_dict  
        
    def enablesecureUIA():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableSecureUIAPaths" | Select-Object EnableSecureUIAPaths')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['enablesecureUIA'] = p_dict
        
    def enablelua():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableLUA" | Select-Object EnableLUA')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['enablelua'] = p_dict  
        
    def promptsecure():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "PromptOnSecureDesktop" | Select-Object PromptOnSecureDesktop')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['promptsecure'] = p_dict
        
    def enablevirtual():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableVirtualization" | Select-Object EnableVirtualization')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['enablevirtual'] = p_dict
        
    def combrowser():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\Browser -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['combrowser'] = p_dict  
        
    def mapsbroker():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\MapsBroker -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['mapsbroker'] = p_dict   
        
    def lfsvc():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\lfsvc -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lfsvc'] = p_dict 
        
    def shareaccess():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\SharedAccess -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['shareaccess'] = p_dict   
        
    def lltdsvc():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\lltdsvc -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['lltdsvc'] = p_dict 
        
    def msis():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\MSiSCSI -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['msis'] = p_dict 
        
    def sshd():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\sshd -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['sshd'] = p_dict 
        
    def wercplsupport():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\wercplsupport -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['wercplsupport'] = p_dict
        
    def RasAuto():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\RasAuto -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RasAuto'] = p_dict
        
    def SessionEnv():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\SessionEnv -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SessionEnv'] = p_dict
        
    def TermService():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\TermService -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['TermService'] = p_dict
        
    def UmRdpService():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\UmRdpService -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['UmRdpService'] = p_dict  
        
    def RpcLocator():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\RpcLocator -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RpcLocator'] = p_dict    
        
    def RemoteRegistry():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\RemoteRegistry -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RemoteRegistry'] = p_dict
        
    def RemoteAccess():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\RemoteAccess -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RemoteAccess'] = p_dict
        
    def LanmanServer():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer -Name "Start" | Select-Object Start')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['LanmanServer'] = p_dict
        
        
    def sealsecure():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\Netlogon\Parameters -Name "SealSecureChannel" | Select-Object SealSecureChannel')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")

        p_dict = dict([p_list])
        config['sealsecure'] = p_dict
        
    def signsecure():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\Netlogon\Parameters -Name "SignSecureChannel" | Select-Object SignSecureChannel')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['signsecure'] = p_dict
        
    def disablepasschange():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\Netlogon\Parameters -Name "DisablePasswordChange" | Select-Object DisablePasswordChange')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disablepasschange'] = p_dict
        
    def machinemaxpasswrdage():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\Netlogon\Parameters -Name "MaximumPasswordAge" | Select-Object MaximumPasswordAge')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['machinemaxpasswrdage'] = p_dict
        
    def requirestrongkey():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\\Netlogon\Parameters -Name "RequireStrongKey" | Select-Object RequireStrongKey')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['requirestrongkey'] = p_dict 
    
    def autorestartsignon():
        p = session.run_ps('Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "DisableAutomaticRestartSignOn" | Select-Object DisableAutomaticRestartSignOn')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['autorestartsignon'] = p_dict 
        
    def cachedlogons():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" | Select-Object CachedLogonsCount')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['cachedlogons'] = p_dict   
        
    def passexpirywarn():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" | Select-Object PasswordExpiryWarning')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['passexpirywarn'] = p_dict
        
    def scremove():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" | Select-Object ScRemoveOption')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['scremove'] = p_dict  
        
    def disableexceptionchainvalid():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" | Select-Object DisableExceptionChainValidation')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disableexceptionchainvalid'] = p_dict  
        
    def ObCaseInsensitive():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ObCaseInsensitive" | Select-Object ObCaseInsensitive')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ObCaseInsensitive'] = p_dict   
        
    def forceunlocklog():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" | Select-Object ForceUnlockLogon')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['forceunlocklog'] = p_dict 
        
    def restrictanonsam():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" | Select-Object RestrictAnonymousSAM')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['restrictanonsam'] = p_dict  
        
    def shutdownnologon():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" | Select-Object ShutdownWithoutLogon')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['shutdownnologon'] = p_dict  
        
    def ProtectionMode():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" | Select-Object ProtectionMode')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ProtectionMode'] = p_dict    
            
    complexity()
    maxpassage()
    minpassage()
    minplength()
    phistorycount()
    reverseencrypt()
    lockoutduration()
    lockoutobserve()
    lockoutcount()
    limitpass()
    crashonaudit()
    disablecad()
    nousername()
    legaltext()
    legalcaption()
    securitysig()
    enablesecuritysig()
    enableplainpass()
    serverautodisconnect()
    serversecuritysig()
    serverenablesecuritysig()
    serverenableforcelogoff()
    screensaveractive()
    screensaversecure()
    screensavertimeout()
    anonymousno()
    disabledcreds()
    includeanon()
    restrictnull()
    forceguest()
    nolmhash()
    ldapintergrity()
    behavioradmin()
    behavioruser()
    installdetect()
    enablesecureUIA()
    enablelua()
    promptsecure()
    enablevirtual()
    combrowser()
    mapsbroker()
    lfsvc()
    shareaccess()
    lltdsvc()
    msis()
    sshd()
    wercplsupport()
    RasAuto()
    SessionEnv()
    TermService()
    UmRdpService()
    RpcLocator()
    RemoteRegistry()
    RemoteAccess()
    LanmanServer()
    sealsecure()
    signsecure()
    disablepasschange()
    machinemaxpasswrdage()
    requirestrongkey()
    autorestartsignon()
    cachedlogons()
    passexpirywarn()
    scremove()
    disableexceptionchainvalid()
    ObCaseInsensitive()
    forceunlocklog()
    restrictanonsam()
    shutdownnologon()
    ProtectionMode()
    
    with open(timestr,'w') as configfile:
        config.write(configfile)
        
    config.read(timestr)
    count = 0
    count2 = 0
    print("\n")
    print("==============================================================")
    print("\n")
    print("Windows Controls \n")
    
    if(config['complexity']['ComplexityEnabled'] == "True"):
        Stat1 = "No need to change Control: ComplexityEnabled \n"
        count = count + 1
    
    else:
        Stat1 = "Setting 'ComplexityEnabled' requires change: False to True \n"
        count2 = count2 + 1
    
    if(config['maxpage']['MaxPasswordAge'] == "42.00:00:00"):
        Stat2 = "No need to change Control: Maximum Password Age \n"
        count = count + 1
    
    else:
        Stat2 = "Setting 'MaxPasswordAge' requires change: Set value to equal to or more than 42.00 \n"
        count2 = count2 + 1
        
    if(config['minpage']['MinPasswordAge'] == "1.00:00:00"):
        Stat3 = "No need to change Control: Minimum Password Age \n"
        count = count + 1
    
    else:
        Stat3 = "Setting 'MinPasswordAge' requires change: Set value to equal to or more than 1.00 \n"
        count2 = count2 + 1
        
    if(int(config['minplength']['MinPasswordLength']) >= 14):
        Stat4 = "No need to change Control: MinPasswordLength \n"
        count = count + 1
        
    else:
        Stat4 = "Setting 'MinPasswordLength' requires change: Set value to equal to or more than 14 \n"
        count2 = count2 + 1
            
    if(int(config['phistorycount']['PasswordHistoryCount']) >= 24):
        Stat5 = "No need to change Control: PasswordHistoryCount \n"
        count = count + 1
            
    else:
        Stat5 = "Setting 'PasswordHistoryCount' requires change: Set value to equal to or more than 24 \n"
        count2 = count2 + 1
                
    if(config['reverseencrypt']['ReversibleEncryptionEnabled'] == "False"):
        Stat6 = "No need to change Control: ReversibleEncryptionEnabled \n"
        count = count + 1
                
    else:
        Stat6 = "Setting 'ReversibleEncryptionEnabled' requires change: True to False \n"
        count2 = count2 + 1
                    
    if(config['lockouttime']['LockoutDuration'] == "00:30:00"):
        Stat7 = "No need to change Control: LockoutDuration \n"
        count = count + 1
                    
    else:
        Stat7 = "Setting 'LockoutDuration' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                        
    if(config['lockoutobservetime']['LockoutObservationWindow'] == "00:30:00"):
        Stat8 = "No need to change Control: LockoutObservationWindow \n"
        count = count + 1
                        
    else:
        Stat8 = "Setting 'LockoutObservationWindow' requires change: Set value to 15 or more minutes \n"
        count2 = count2 + 1
                            
    if(int(config['lockoutthreshold']['LockoutThreshold']) <= 10 and int(config['lockoutthreshold']['LockoutThreshold']) != 0 ):
        Stat9 = "No need to change Control: LockoutThreshold \n"
        count = count + 1
                            
    else:
        Stat9 = "Setting 'LockoutThreshold' requires change: Set value to 10 or fewer invalid logon attempts but not 0 \n"
        count2 = count2 + 1
                                
    if(int(config['limitpass']['limitblankpassworduse']) == 1):
        Stat10 = "No need to change Control: LimitBlankPasswordUse \n"
        count = count + 1
                            
    else:
        Stat10 = "Setting 'LimitBlankPasswordUse' requires change: Set value to 1 OR Enable in Accounts: Limit local account use of blank passwords to console logon only in GPO \n"
        count2 = count2 + 1
    
    if(int(config['crashonaudit']['crashonauditfail']) == 0):
        Stat11 = "No need to change Control: CrashOnAuditFail \n"
        count = count + 1
                                
    else:
        Stat11 = "Setting 'CrashOnAuditFail' requires change: Set value to 0 OR Ensure in Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['disablecad']['disablecad']) == 0):
        Stat12 = "No need to change Control: DisableCAD \n"
        count = count + 1
                                    
    else:
        Stat12 = "Setting 'DisableCAD' requires change: Set value to 0 OR Ensure in 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['nousername']['dontdisplaylastusername']) == 1):
        Stat13 = "No need to change Control: DontDisplayLastUserName \n"
        count = count + 1
                                        
    else:
        Stat13 = "Setting 'DontDisplayLastUserName' requires change: Set value to 1 OR Ensure in 'Interactive logon: Don't display last signed-in' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1
        
    if(config['legaltext']['legalnoticetext'] != "" ):
        Stat14 = "No need to change Control: LegalNoticeText \n"
        count = count + 1
                                            
    else:
        Stat14 = "Setting 'LegalNoticeText' requires change: Configure 'Interactive logon: Message text for users attempting to log on' in GPO \n"
        count2 = count2 + 1 
        
    if(config['legalcaption']['legalnoticecaption'] != "" ):
        Stat15 = "No need to change Control: LegalNoticeCaption \n"
        count = count + 1
                                                
    else:
        Stat15 = "Setting 'LegalNoticeCaption' requires change: Configure 'Interactive logon: Message title for users attempting to log on' in GPO \n"
        count2 = count2 + 1
        
    if(int(config['securitysig']['requiresecuritysignature']) == 1 ):
        Stat16 = "No need to change Control: RequireSecuritySignature \n"
        count = count + 1
                                                    
    else:
        Stat16 = "Setting 'RequireSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['enablesecuritysig']['enablesecuritysignature']) == 1 ):
        Stat17 = "No need to change Control: EnableSecuritySignature \n"
        count = count + 1
                                                        
    else:
        Stat17 = "Setting 'EnableSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['enablesplainpass']['enableplaintextpassword']) == 0 ):
        Stat18 = "No need to change Control: EnablePlainTextPassword \n"
        count = count + 1
                                                            
    else:
        Stat18 = "Setting 'EnablePlainTextPassword' requires change: Set value to 0 OR Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' in GPO \n"
        count2 = count2 + 1  
        
    if(int(config['serverautodisconnect']['autodisconnect']) <= 15 ):
        Stat19 = "No need to change Control: Server AutoDisconnect \n"
        count = count + 1
                                                                
    else:
        Stat19 = "Setting 'Server AutoDisconnect' requires change: Set value to fewer or lesser than 15 OR Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)' in GPO \n"
        count2 = count2 + 1 
        
    if(int(config['serversecuritysig']['requiresecuritysignature']) == 1 ):
        Stat20 = "No need to change Control: Server RequireSecuritySignature \n"
        count = count + 1
                                                                    
    else:
        Stat20 = "Setting 'Server RequireSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['serverenablesecuritysig']['enablesecuritysignature']) == 1 ):
        Stat21 = "No need to change Control: Server EnableSecuritySignature \n"
        count = count + 1
                                                                        
    else:
        Stat21 = "Setting 'Server EnableSecuritySignature' requires change: Set value to 1 OR Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['serverenableforcelogoff']['enableforcedlogoff']) == 1 ):
        Stat22 = "No need to change Control: Server enableforcedlogoff \n"
        count = count + 1
                                                                            
    else:
        Stat22 = "Setting 'Server enableforcedlogoff' requires change: Set value to 1 OR Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(config['screensaveractive']['screensaveactive'] != "" ):
        Stat23 = "No need to change Control: screensaveactive \n"
        count = count + 1
                                                                                
    else:
        Stat23 = "Setting 'screensaveactive' requires change: Ensure 'Enable screen saver' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(config['screensaversecure']['screensaverissecure'] != "" ):
        Stat24 = "No need to change Control: screensaverissecure \n"
        count = count + 1
                                                                                    
    else:
        Stat24 = "Setting 'screensaverissecure' requires change: Ensure 'Password protect the screen saver' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
    
    if(config['screensavertimeout']['screensavertimeout'] != "" ):
        Stat25 = "No need to change Control: screensavertimeout \n"
        count = count + 1
                                                                                        
    else:
        Stat25 = "Setting 'screensavertimeout' requires change: Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['anonymousno']['restrictanonymous']) == 1 ):
        Stat26 = "No need to change Control: RestrictAnonymous \n"
        count = count + 1
                                                                                            
    else:
        Stat26 = "Setting 'RestrictAnonymous' requires change: Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['disabledcreds']['disabledomaincreds']) == 1 ):
        Stat27 = "No need to change Control: DisableDomainCreds \n"
        count = count + 1
                                                                                                
    else:
        Stat27 = "Setting 'DisableDomainCreds' requires change: Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['includeanon']['everyoneincludesanonymous']) == 0 ):
        Stat28 = "No need to change Control: EveryoneIncludesAnonymous \n"
        count = count + 1
                                                                                                    
    else:
        Stat28 = "Setting 'EveryoneIncludesAnonymous' requires change: Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['restrictnull']['restrictnullsessaccess']) == 1 ):
        Stat29 = "No need to change Control: RestrictNullSessAccess \n"
        count = count + 1
                                                                                                        
    else:
        Stat29 = "Setting 'RestrictNullSessAccess' requires change: Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['forceguest']['forceguest']) == 0 ):
        Stat30 = "No need to change Control: ForceGuest \n"
        count = count + 1
                                                                                                            
    else:
        Stat30 = "Setting 'ForceGuest' requires change: Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['nolmhash']['nolmhash']) == 1 ):
        Stat31 = "No need to change Control: NoLMHash \n"
        count = count + 1
                                                                                                                
    else:
        Stat31 = "Setting 'NoLMHash' requires change: Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['ldapintergrity']['ldapclientintegrity']) >= 1 ):
        Stat32 = "No need to change Control: LDAPClientIntegrity \n"
        count = count + 1
                                                                                                                    
    else:
        Stat32 = "Setting 'LDAPClientIntegrity' requires change: Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['behavioradmin']['consentpromptbehavioradmin']) >= 1 ):
        Stat33 = "No need to change Control: ConsentPromptBehaviorAdmin \n"
        count = count + 1
                                                                                                                            
    else:
        Stat33 = "Setting 'ConsentPromptBehaviorAdmin' requires change: Ensure 'User Account Control: Behavior of the elevation for consent on the secure desktop' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['behavioruser']['consentpromptbehavioruser']) >= 1 ):
        Stat34 = "No need to change Control: ConsentPromptBehaviorUser \n"
        count = count + 1
                                                                                                                                
    else:
        Stat34 = "Setting 'ConsentPromptBehaviorUser' requires change: Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['installdetect']['enableinstallerdetection']) >= 1 ):
        Stat35 = "No need to change Control: EnableInstallerDetection \n"
        count = count + 1
                                                                                                                                    
    else:
        Stat35 = "Setting 'EnableInstallerDetection' requires change: Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['enablesecureUIA']['enablesecureuiapaths']) >= 1 ):
        Stat36 = "No need to change Control: EnableSecureUIAPaths \n"
        count = count + 1
                                                                                                                                        
    else:
        Stat36 = "Setting 'EnableSecureUIAPaths' requires change: Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['enablelua']['enablelua']) >= 1 ):
        Stat37 = "No need to change Control: EnableLUA \n"
        count = count + 1
                                                                                                                                            
    else:
        Stat37 = "Setting 'EnableLUA' requires change: Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['promptsecure']['promptonsecuredesktop']) >= 1 ):
        Stat38 = "No need to change Control: PromptOnSecureDesktop \n"
        count = count + 1
                                                                                                                                                
    else:
        Stat38 = "Setting 'PromptOnSecureDesktop' requires change: Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['enablevirtual']['enablevirtualization']) >= 1 ):
        Stat39 = "No need to change Control: EnableVirtualization \n"
        count = count + 1
                                                                                                                                                    
    else:
        Stat39 = "Setting 'EnableVirtualization' requires change: Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['combrowser']['start']) == 2 or int(config['combrowser']['start']) == 4 ):
        Stat40 = "No need to change Control: Browser \n"
        count = count + 1
                                                                                                                                                        
    else:
        Stat40 = "Setting 'Browser' requires change: Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['mapsbroker']['start']) == 2):
        Stat41 = "No need to change Control: MapsBroker \n"
        count = count + 1
                                                                                                                                                            
    else:
        Stat41 = "Setting 'MapsBroker' requires change: Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1   
        
    if(int(config['lfsvc']['start']) == 3):
        Stat42 = "No need to change Control: lfsvc \n"
        count = count + 1
                                                                                                                                                                
    else:
        Stat42 = "Setting 'lfsvc' requires change: Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['shareaccess']['start']) == 2):
        Stat43 = "No need to change Control: SharedAccess \n"
        count = count + 1
                                                                                                                                                                    
    else:
        Stat43 = "Setting 'SharedAccess' requires change: Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['lltdsvc']['start']) == 3):
        Stat44 = "No need to change Control: lltdsvc \n"
        count = count + 1
                                                                                                                                                                        
    else:
        Stat44 = "Setting 'lltdsvc' requires change: Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['msis']['start']) == 3):
        Stat45 = "No need to change Control: MSiSCSI \n"
        count = count + 1
                                                                                                                                                                            
    else:
        Stat45 = "Setting 'MSiSCSI' requires change: Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['sshd']['start']) == 0 or int(config['sshd']['start'] == 4 )):
        Stat46 = "No need to change Control: sshd \n"
        count = count + 1
                                                                                                                                                                                
    else:
        Stat46 = "Setting 'sshd' requires change: Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'  in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['wercplsupport']['start']) == 0 ):
        Stat47 = "No need to change Control: wercplsupport \n"
        count = count + 1
                                                                                                                                                                                    
    else:
        Stat47 = "Setting 'wercplsupport' requires change: Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['RasAuto']['start']) == 0 ):
        Stat48 = "No need to change Control: RasAuto \n"
        count = count + 1
                                                                                                                                                                                        
    else:
        Stat48 = "Setting 'RasAuto' requires change: Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['SessionEnv']['start']) == 3 ):
        Stat49 = "No need to change Control: SessionEnv \n"
        count = count + 1
                                                                                                                                                                                            
    else:
        Stat49 = "Setting 'SessionEnv' requires change: Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['TermService']['start']) == 3 ):
        Stat50 = "No need to change Control: TermService \n"
        count = count + 1
                                                                                                                                                                                                
    else:
        Stat50 = "Setting 'TermService' requires change: Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['UmRdpService']['start']) == 3 ):
        Stat51 = "No need to change Control: UmRdpService \n"
        count = count + 1
                                                                                                                                                                                                    
    else:
        Stat51 = "Setting 'UmRdpService' requires change:Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['RpcLocator']['start']) == 3 ):
        Stat52 = "No need to change Control: RpcLocator \n"
        count = count + 1
                                                                                                                                                                                                        
    else:
        Stat52 = "Setting 'RpcLocator' requires change: Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['RemoteRegistry']['start']) == 2 ):
        Stat53 = "No need to change Control: RemoteRegistry \n"
        count = count + 1
                                                                                                                                                                                                            
    else:
        Stat53 = "Setting 'RemoteRegistry' requires change: Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['RemoteAccess']['start']) == 4 ):
        Stat54 = "No need to change Control: RemoteAccess \n"
        count = count + 1
                                                                                                                                                                                                                
    else:
        Stat54 = "Setting 'RemoteAccess' requires change: Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['LanmanServer']['start']) == 4 ):
        Stat55 = "No need to change Control: LanmanServer \n"
        count = count + 1
                                                                                                                                                                                                                    
    else:
        Stat55 = "Setting 'LanmanServer' requires change: Ensure 'Server (LanmanServer)' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['sealsecure']['sealsecurechannel']) == 1 ):
        Stat56 = "No need to change Control: SealSecureChannel \n"
        count = count + 1
                                                                                                                                                                                                                        
    else:
        Stat56 = "Setting 'SealSecureChannel' requires change: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['signsecure']['signsecurechannel']) == 1 ):
        Stat57 = "No need to change Control: SignSecureChannel \n"
        count = count + 1
                                                                                                                                                                                                                            
    else:
        Stat57 = "Setting 'SignSecureChannel' requires change: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['disablepasschange']['disablepasswordchange']) == 1 ):
        Stat58 = "No need to change Control: DisablePasswordChange \n"
        count = count + 1
                                                                                                                                                                                                                               
    else:
        Stat58 = "Setting 'DisablePasswordChange' requires change: Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['machinemaxpasswrdage']['maximumpasswordage']) <= 30 and int(config['machinemaxpasswrdage']['maximumpasswordage']) != 0 ):
        Stat59 = "No need to change Control: MaximumPasswordAge \n"
        count = count + 1
                                                                                                                                                                                                                                   
    else:
        Stat59 = "Setting 'MaximumPasswordAge' requires change: Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['requirestrongkey']['requirestrongkey']) == 1):
        Stat60 = "No need to change Control: RequireStrongKey \n"
        count = count + 1
                                                                                                                                                                                                                                       
    else:
        Stat60 = "Setting 'RequireStrongKey' requires change: Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1
    
    if(int(config['autorestartsignon']['disableautomaticrestartsignon']) == 0):
        Stat61 = "No need to change Control: DisableAutomaticRestartSignOn \n"
        count = count + 1
                                                                                                                                                                                                                                           
    else:
        Stat61 = "Setting 'DisableAutomaticRestartSignOn' requires change: Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1    
        
    if(int(config['cachedlogons']['cachedlogonscount']) <= 4):
        Stat62 = "No need to change Control: CachedLogonsCount \n"
        count = count + 1
                                                                                                                                                                                                                                               
    else:
        Stat62 = "Setting 'CachedLogonsCount' requires change: Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' in GPO \n \n"
        count2 = count2 + 1
        
    if(int(config['passexpirywarn']['passwordexpirywarning']) >= 5 or int(config['passexpirywarn']['passwordexpirywarning']) <= 14):
        Stat63 = "No need to change Control: PasswordExpiryWarning \n"
        count = count + 1
                                                                                                                                                                                                                                                   
    else:
        Stat63 = "Setting 'PasswordExpiryWarning' requires change: 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['scremove']['scremoveoption']) >= 1):
        Stat64 = "No need to change Control: ScRemoveOption \n"
        count = count + 1
                                                                                                                                                                                                                                                   
    else:
        Stat64 = "Setting 'ScRemoveOption' requires change: Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher in GPO \n \n"
        count2 = count2 + 1   
        
    if(int(config['disableexceptionchainvalid']['disableexceptionchainvalidation']) == 1):
        Stat65 = "No need to change Control: DisableExceptionChainValidation \n"
        count = count + 1
                                                                                                                                                                                                                                                       
    else:
        Stat65 = "Setting 'DisableExceptionChainValidation' requires change: Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1   
        
    if(int(config['ObCaseInsensitive']['obcaseinsensitive']) == 1):
        Stat66 = "No need to change Control: ObCaseInsensitive \n"
        count = count + 1
                                                                                                                                                                                                                                                           
    else:
        Stat66 = "Setting 'ObCaseInsensitive' requires change: Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['forceunlocklog']['forceunlocklogon']) == 1):
        Stat67 = "No need to change Control: ForceUnlockLogon \n"
        count = count + 1
                                                                                                                                                                                                                                                               
    else:
        Stat67 = "Setting 'ForceUnlockLogon' requires change: Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1  
        
    if(int(config['restrictanonsam']['restrictanonymoussam']) == 1):
        Stat68 = "No need to change Control: RestrictAnonymousSAM \n"
        count = count + 1
                                                                                                                                                                                                                                                                   
    else:
        Stat68 = "Setting 'RestrictAnonymousSAM' requires change: Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['shutdownnologon']['shutdownwithoutlogon']) == 0):
        Stat69 = "No need to change Control: ShutdownWithoutLogon \n"
        count = count + 1
                                                                                                                                                                                                                                                                       
    else:
        Stat69 = "Setting 'ShutdownWithoutLogon' requires change: Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled' in GPO \n \n"
        count2 = count2 + 1 
        
    if(int(config['ProtectionMode']['protectionmode']) == 1):
        Stat70 = "No need to change Control: ProtectionMode \n"
        count = count + 1
                                                                                                                                                                                                                                                                           
    else:
        Stat70 = "Setting 'ProtectionMode' requires change: Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled' in GPO \n \n"
        count2 = count2 + 1    
        
    #print(config.sections())
    print("\n")
    print("============================================================== \n")     
    

    listbox.insert(0, "Writing to " + timestr + " in program folder.")
    listbox.insert(1, " ")
    listbox.insert(2, "Account Security + Remediations")
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
    listbox.insert(4, Stat10)
    listbox.insert(4, Stat11)
    listbox.insert(4, Stat12)
    listbox.insert(4, Stat13)
    listbox.insert(4, Stat14)
    listbox.insert(4, Stat15)
    listbox.insert(4, Stat16)
    listbox.insert(4, Stat17)
    listbox.insert(4, Stat18)
    listbox.insert(4, Stat19)
    listbox.insert(4, Stat20)
    listbox.insert(4, Stat21)
    listbox.insert(4, Stat22)
    listbox.insert(4, Stat23)
    listbox.insert(4, Stat24)
    listbox.insert(4, Stat25)
    listbox.insert(4, Stat26)
    listbox.insert(4, Stat27)
    listbox.insert(4, Stat28)
    listbox.insert(4, Stat29)
    listbox.insert(4, Stat30)
    listbox.insert(4, Stat31)
    listbox.insert(4, Stat32)
    listbox.insert(4, Stat33)
    listbox.insert(4, Stat34)
    listbox.insert(4, Stat35)
    listbox.insert(4, Stat36)
    listbox.insert(4, Stat37)
    listbox.insert(4, Stat38)
    listbox.insert(4, Stat39)
    listbox.insert(4, Stat40)
    listbox.insert(4, Stat41)
    listbox.insert(4, Stat42)
    listbox.insert(4, Stat43)
    listbox.insert(4, Stat44)
    listbox.insert(4, Stat45)
    listbox.insert(4, Stat46)
    listbox.insert(4, Stat47)
    listbox.insert(4, Stat48)
    listbox.insert(4, Stat49)
    listbox.insert(4, Stat50)
    listbox.insert(4, Stat51)
    listbox.insert(4, Stat52)
    listbox.insert(4, Stat53)
    listbox.insert(4, Stat54)
    listbox.insert(4, Stat55)
    listbox.insert(4, Stat56)
    listbox.insert(4, Stat57)
    listbox.insert(4, Stat58)
    listbox.insert(4, Stat59)
    listbox.insert(4, Stat60)
    listbox.insert(4, Stat61)
    listbox.insert(4, Stat62)
    listbox.insert(4, Stat63)
    listbox.insert(4, Stat64)
    listbox.insert(4, Stat65)
    listbox.insert(4, Stat66)
    listbox.insert(4, Stat67)
    listbox.insert(4, Stat68)
    listbox.insert(4, Stat69)
    listbox.insert(4, Stat70)
    
    
    listbox2.insert(0, "\nNumber of Compliant controls") 
    listbox2.insert(1, "--> " + str(count)) 
    listbox2.insert(2, "Number of Non-Compliant controls") 
    listbox2.insert(3, "--> " + str(count2))  
    
def saveScan():
    date = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    datestr = date + " Windows Report.txt"
    with open(datestr, 'w') as f:
        f.write("--Configuration Scan--\n\n")
        f.write('\n'.join(listbox.get('0', 'end')))
        f.write('\n'.join(listbox2.get('0', 'end')))
        f.close()  
        
def saveScan2():
    date = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    datestr = date + " Browser Report.txt"
    with open(datestr, 'w') as f:
        f.write("--Configuration Scan--\n\n")
        f.write('\n'.join(listbox3.get('0', 'end')))
        f.write('\n'.join(listbox4.get('0', 'end')))
        f.close()    

def deleteScan():
    listbox.delete('0', 'end')
    listbox2.delete('0', 'end') 
    
def deleteScan2():
    listbox3.delete('0', 'end')
    listbox4.delete('0', 'end')    
     
def googlescan():
    host2 = IP2.get()
    domain2 = Domain2.get()
    user2 = username2.get()
    password2 = passwd2.get()
    
    session = winrm.Session(host2, auth=('{}@{}' .format(user2 ,domain2), password2), transport='ntlm') 
    
    import time
    import configparser
    config = configparser.ConfigParser()
    time = time.strftime("%Y_%m_%d-%I_%M_%S_%p")
    timestr = time + " Browser Settings.ini"
    
    def remotehostcurtain():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RemoteAccessHostRequireCurtain" | Select-Object RemoteAccessHostRequireCurtain')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['remotehostcurtain'] = p_dict
        
    def remotehostuiremoteassist():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RemoteAccessHostAllowUiAccessForRemoteAssistance" | Select-Object RemoteAccessHostAllowUiAccessForRemoteAssistance')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['remotehostuiremoteassist'] = p_dict
        
    def BackgroundModeEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "BackgroundModeEnabled" | Select-Object BackgroundModeEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['BackgroundModeEnabled'] = p_dict 
        
    def PromptForDownloadLocation():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "PromptForDownloadLocation" | Select-Object PromptForDownloadLocation')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['PromptForDownloadLocation'] = p_dict  
        
    def savebrowserhistory():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" | Select-Object SavingBrowserHistoryDisabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['savebrowserhistory'] = p_dict  
        
    def ComponentUpdatesEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "ComponentUpdatesEnabled" | Select-Object ComponentUpdatesEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ComponentUpdatesEnabled'] = p_dict 
    
    def ThirdPartyBlockingEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "ThirdPartyBlockingEnabled" | Select-Object ThirdPartyBlockingEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ThirdPartyBlockingEnabled'] = p_dict 
        
    def SuppressUnsupportedOSWarning():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SuppressUnsupportedOSWarning" | Select-Object SuppressUnsupportedOSWarning')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SuppressUnsupportedOSWarning'] = p_dict
        
    def EnableOnlineRevocationChecks():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "EnableOnlineRevocationChecks" | Select-Object EnableOnlineRevocationChecks')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['EnableOnlineRevocationChecks'] = p_dict
        
    def SafeSitesFilterBehavior():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SafeSitesFilterBehavior" | Select-Object SafeSitesFilterBehavior')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SafeSitesFilterBehavior'] = p_dict  
        
    def DefaultNotificationsSetting():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DefaultNotificationsSetting" | Select-Object DefaultNotificationsSetting')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['DefaultNotificationsSetting'] = p_dict  
        
    def Defaultbluetooth():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DefaultWebBluetoothGuardSetting" | Select-Object DefaultWebBluetoothGuardSetting')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['Defaultbluetooth'] = p_dict 
        
    def DefaultWebUsbGuardSetting():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DefaultWebUsbGuardSetting" | Select-Object DefaultWebUsbGuardSetting')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['DefaultWebUsbGuardSetting'] = p_dict  
        
    def PasswordManagerEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "PasswordManagerEnabled" | Select-Object PasswordManagerEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------", "-")
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['PasswordManagerEnabled'] = p_dict  
        
    def AuthSchemes():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "AuthSchemes" | Select-Object AuthSchemes')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------", "-")   
        p_list = p_output.split("-")
        
        for i in p_list:
            p_dict = dict([p_list])
            config['AuthSchemes'] = p_dict
        
    def CloudPrintProxyEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "CloudPrintProxyEnabled" | Select-Object CloudPrintProxyEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['CloudPrintProxyEnabled'] = p_dict 
        
    def SitePerProcess():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SitePerProcess" | Select-Object SitePerProcess')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SitePerProcess'] = p_dict   
        
    def DownloadRestrictions():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DownloadRestrictions" | Select-Object DownloadRestrictions')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['DownloadRestrictions'] = p_dict
        
    def disablesafebrowsing():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DisableSafeBrowsingProceedAnyway" | Select-Object DisableSafeBrowsingProceedAnyway')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['disablesafebrowsing'] = p_dict  
        
    def RelaunchNotification():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification" | Select-Object RelaunchNotification')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RelaunchNotification'] = p_dict   
        
    def RelaunchNotificationPeriod():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod" | Select-Object RelaunchNotificationPeriod')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['RelaunchNotificationPeriod'] = p_dict    
        
    def revocationchecklocalanchor():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RequireOnlineRevocationChecksForLocalAnchors" | Select-Object RequireOnlineRevocationChecksForLocalAnchors')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['revocationchecklocalanchor'] = p_dict   
        
    def ChromeCleanupEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" | Select-Object ChromeCleanupEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ChromeCleanupEnabled'] = p_dict    
        
    def BuiltInDnsClientEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "BuiltInDnsClientEnabled" | Select-Object BuiltInDnsClientEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['BuiltInDnsClientEnabled'] = p_dict 
        
    def DefaultCookiesSetting():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DefaultCookiesSetting" | Select-Object DefaultCookiesSetting')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['DefaultCookiesSetting'] = p_dict  
        
    def DefaultGeolocationSetting():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "DefaultGeolocationSetting" | Select-Object DefaultGeolocationSetting')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['DefaultGeolocationSetting'] = p_dict 
        
    def EnableMediaRouter():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "EnableMediaRouter" | Select-Object EnableMediaRouter')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['EnableMediaRouter'] = p_dict 
        
    def BlockThirdPartyCookies():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "BlockThirdPartyCookies" | Select-Object BlockThirdPartyCookies')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['BlockThirdPartyCookies'] = p_dict  
        
    def MetricsReportingEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" | Select-Object MetricsReportingEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['MetricsReportingEnabled'] = p_dict
        
    def chromecleanupreport():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" | Select-Object ChromeCleanupReportingEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['chromecleanupreport'] = p_dict 
        
    def BrowserSignin():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "BrowserSignin" | Select-Object BrowserSignin')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['BrowserSignin'] = p_dict 
        
    def TranslateEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "TranslateEnabled" | Select-Object TranslateEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['TranslateEnabled'] = p_dict    
        
    def NetworkPredictionOptions():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "NetworkPredictionOptions" | Select-Object NetworkPredictionOptions')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['NetworkPredictionOptions'] = p_dict  
        
    def SearchSuggestEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SearchSuggestEnabled" | Select-Object SearchSuggestEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SearchSuggestEnabled'] = p_dict   
        
    def SpellCheckServiceEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SpellCheckServiceEnabled" | Select-Object SpellCheckServiceEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SpellCheckServiceEnabled'] = p_dict 
        
    def AlternateErrorPagesEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "AlternateErrorPagesEnabled" | Select-Object AlternateErrorPagesEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['AlternateErrorPagesEnabled'] = p_dict  
        
    def SyncDisabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SyncDisabled" | Select-Object SyncDisabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['SyncDisabled'] = p_dict   
        
    def safebrowsingtrustedsource():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowsingForTrustedSourcesEnabled" | Select-Object SafeBrowsingForTrustedSourcesEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("------------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['safebrowsingtrustedsource'] = p_dict 
        
    def urlkeyeddatacollect():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "UrlKeyedAnonymizedDataCollectionEnabled" | Select-Object UrlKeyedAnonymizedDataCollectionEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['urlkeyeddatacollect'] = p_dict  
        
    def allowdeletebrowserhistory():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "AllowDeletingBrowserHistory" | Select-Object AllowDeletingBrowserHistory')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['allowdeletebrowserhistory'] = p_dict   
        
    def remoteaccessfirewalltraverse():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RemoteAccessHostFirewallTraversal" | Select-Object RemoteAccessHostFirewallTraversal')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("---------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['remoteaccessfirewalltraverse'] = p_dict   
        
    def remoteaccessclientpair():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RemoteAccessHostAllowClientPairing" | Select-Object RemoteAccessHostAllowClientPairing')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['remoteaccessclientpair'] = p_dict 
        
    def remoteaccessrelayconnect():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "RemoteAccessHostAllowRelayedConnection" | Select-Object RemoteAccessHostAllowRelayedConnection')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['remoteaccessrelayconnect'] = p_dict  
        
    def CloudPrintSubmitEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "CloudPrintSubmitEnabled" | Select-Object CloudPrintSubmitEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['CloudPrintSubmitEnabled'] = p_dict 
        
    def ImportSavedPasswords():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "ImportSavedPasswords" | Select-Object ImportSavedPasswords')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("--------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['ImportSavedPasswords'] = p_dict   
        
    def AutofillCreditCardEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "AutofillCreditCardEnabled" | Select-Object AutofillCreditCardEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("-------------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['AutofillCreditCardEnabled'] = p_dict 
        
    def AutofillAddressEnabled():
        p = session.run_ps('Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Google\Chrome" -Name "AutofillAddressEnabled" | Select-Object AutofillAddressEnabled')
        p_output = str(p.std_out)
        p_output = p_output.replace("b\'", "")
        p_output = p_output.replace("\\r", "")
        p_output = p_output.replace("\\n", "")
        p_output = p_output.replace("\'", "")
        p_output = p_output.replace(" ", "")
        p_output = p_output.replace("----------------------", "-")   
        p_list = p_output.split("-")
        
        p_dict = dict([p_list])
        config['AutofillAddressEnabled'] = p_dict    
            
    
    remotehostcurtain()
    remotehostuiremoteassist()
    BackgroundModeEnabled()
    PromptForDownloadLocation()
    savebrowserhistory()
    ComponentUpdatesEnabled()
    ThirdPartyBlockingEnabled()
    SuppressUnsupportedOSWarning()
    EnableOnlineRevocationChecks()
    SafeSitesFilterBehavior()
    DefaultNotificationsSetting()
    Defaultbluetooth()
    DefaultWebUsbGuardSetting()
    PasswordManagerEnabled()
    AuthSchemes()
    CloudPrintProxyEnabled()
    SitePerProcess()
    DownloadRestrictions()
    disablesafebrowsing()
    RelaunchNotification()
    RelaunchNotificationPeriod()
    revocationchecklocalanchor()
    ChromeCleanupEnabled()
    BuiltInDnsClientEnabled()
    DefaultCookiesSetting()
    DefaultGeolocationSetting()
    EnableMediaRouter()
    BlockThirdPartyCookies()
    MetricsReportingEnabled()
    chromecleanupreport()
    BrowserSignin()
    TranslateEnabled()
    NetworkPredictionOptions()
    SearchSuggestEnabled()
    SpellCheckServiceEnabled()
    AlternateErrorPagesEnabled()
    SyncDisabled()
    safebrowsingtrustedsource()
    urlkeyeddatacollect()
    allowdeletebrowserhistory()
    remoteaccessfirewalltraverse()
    remoteaccessclientpair()
    remoteaccessrelayconnect()
    CloudPrintSubmitEnabled()
    ImportSavedPasswords()
    AutofillCreditCardEnabled()
    AutofillAddressEnabled()

    with open(timestr,'w') as configfile:
        config.write(configfile)
        
    config.read(timestr)
    count = 0
    count2 = 0
    print("\n")
    print("==============================================================")
    print("\n")
    print("Browser Controls \n")
    
    if(int(config['remotehostcurtain']['remoteaccesshostrequirecurtain']) == 0):
        Stat1 = "No need to change Control: RemoteAccessHostRequireCurtain \n"
        count = count + 1
    
    else:
        Stat1 = "Setting 'RemoteAccessHostRequireCurtain' requires change: 1.1.1 (L1) Ensure 'Enable curtaining of remote access hosts' is set to 'Disabled' \n"
        count2 = count2 + 1
        
    if(int(config['remotehostuiremoteassist']['remoteaccesshostallowuiaccessforremoteassistance']) == 0):
        Stat2 = "No need to change Control: RemoteAccessHostAllowUiAccessForRemoteAssistance \n"
        count = count + 1
        
    else:
        Stat2 = "Setting 'RemoteAccessHostAllowUiAccessForRemoteAssistance' requires change: 1.1.3 (L1) Ensure 'Allow remote users to interact with elevated windows in remote assistance sessions' is set to 'Disabled' \n"
        count2 = count2 + 1    
        
    if(int(config['BackgroundModeEnabled']['backgroundmodeenabled']) == 0):
        Stat3 = "No need to change Control: BackgroundModeEnabled \n"
        count = count + 1
            
    else:
        Stat3 = "Setting 'BackgroundModeEnabled' requires change: 1.2 (L1) Ensure 'Continue running background apps when Google Chrome is closed' is set to 'Disabled' \n"
        count2 = count2 + 1   
        
    if(int(config['PromptForDownloadLocation']['promptfordownloadlocation']) == 1):
        Stat4 = "No need to change Control: PromptForDownloadLocation \n"
        count = count + 1
                
    else:
        Stat4 = "Setting 'PromptForDownloadLocation' requires change: 1.3 (L1) Ensure 'Ask where to save each file before downloading' is set to 'Enabled' \n"
        count2 = count2 + 1  
        
    if(int(config['savebrowserhistory']['savingbrowserhistorydisabled']) == 0):
        Stat5 = "No need to change Control: SavingBrowserHistoryDisabled \n"
        count = count + 1
                
    else:
        Stat5 = "Setting 'SavingBrowserHistoryDisabled' requires change: 1.4 (L1) Ensure 'Disable saving browser history' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['ComponentUpdatesEnabled']['componentupdatesenabled']) == 1):
        Stat6 = "No need to change Control: ComponentUpdatesEnabled \n"
        count = count + 1
                    
    else:
        Stat6 = "Setting 'ComponentUpdatesEnabled' requires change: 1.6 (L1) Ensure 'Enable component updates in Google Chrome' is set to 'Enabled' \n"
        count2 = count2 + 1    
        
    if(int(config['ThirdPartyBlockingEnabled']['thirdpartyblockingenabled']) == 1):
        Stat7 = "No need to change Control: ThirdPartyBlockingEnabled \n"
        count = count + 1
                        
    else:
        Stat7 = "Setting 'ThirdPartyBlockingEnabled' requires change: 1.8 (L1) Ensure 'Enable third party software injection blocking' is set to 'Enabled' \n"
        count2 = count2 + 1 
        
    if(int(config['SuppressUnsupportedOSWarning']['suppressunsupportedoswarning']) == 0):
        Stat8 = "No need to change Control: SuppressUnsupportedOSWarning \n"
        count = count + 1
                            
    else:
        Stat8 = "Setting 'SuppressUnsupportedOSWarning' requires change: 1.10 (L1) Ensure 'Suppress the unsupported OS warning' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['EnableOnlineRevocationChecks']['enableonlinerevocationchecks']) == 0):
        Stat9 = "No need to change Control: EnableOnlineRevocationChecks \n"
        count = count + 1
                                
    else:
        Stat9 = "Setting 'EnableOnlineRevocationChecks' requires change: 1.11 (L1) Ensure 'Whether online OCSP/CRL checks are performed' is set to 'Disabled' \n"
        count2 = count2 + 1
        
    if(int(config['SafeSitesFilterBehavior']['safesitesfilterbehavior']) >= 1):
        Stat10 = "No need to change Control: SafeSitesFilterBehavior \n"
        count = count + 1
                                    
    else:
        Stat10 = "Setting 'SafeSitesFilterBehavior' requires change: 1.13 (L1) Ensure 'Control SafeSites adult content filtering' is set to 'Enabled' with value 'Do not filter sites for adult content' specified \n"
        count2 = count2 + 1  
        
    if(int(config['DefaultNotificationsSetting']['defaultnotificationssetting']) >= 1):
        Stat11 = "No need to change Control: DefaultNotificationsSetting \n"
        count = count + 1
                                        
    else:
        Stat11 = "Setting 'DefaultNotificationsSetting' requires change: 2.2 (L2) Ensure 'Default notification setting' is set to 'Enabled' with 'Do not allow any site to show desktop notifications' \n"
        count2 = count2 + 1  
        
    if(int(config['Defaultbluetooth']['defaultwebbluetoothguardsetting']) >= 1):
        Stat12 = "No need to change Control: DefaultWebBluetoothGuardSetting \n"
        count = count + 1
                                            
    else:
        Stat12 = "Setting 'DefaultWebBluetoothGuardSetting' requires change: 2.3 (L2) Ensure 'Control use of the Web Bluetooth API' is set to 'Enabled' with 'Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API' \n"
        count2 = count2 + 1  
        
    if(int(config['DefaultWebUsbGuardSetting']['defaultwebusbguardsetting']) >= 1):
        Stat13 = "No need to change Control: DefaultWebUsbGuardSetting \n"
        count = count + 1
                                                
    else:
        Stat13 = "Setting 'DefaultWebUsbGuardSetting' requires change: 2.4 (L2) Ensure 'Control use of the WebUSB API' is set to 'Enabled' with 'Do not allow any site to request access to USB devices via the WebUSB API' \n"
        count2 = count2 + 1  
        
    if(int(config['PasswordManagerEnabled']['passwordmanagerenabled']) >= 1):
        Stat14 = "No need to change Control: PasswordManagerEnabled \n"
        count = count + 1
                                                    
    else:
        Stat14 = "Setting 'PasswordManagerEnabled' requires change: 2.8 (L1) Ensure 'Enable saving passwords to the password manager' is Configured \n"
        count2 = count2 + 1  
        
    if(config['AuthSchemes']['authschemes'] != ""):
        Stat15 = "No need to change Control: AuthSchemes \n"
        count = count + 1
                                                        
    else:
        Stat15 = "Setting 'AuthSchemes' requires change: 2.9 (L1) Ensure 'Supported authentication schemes' is set to 'Enabled' (ntlm, negotiate) \n"
        count2 = count2 + 1 
        
    if(int(config['CloudPrintProxyEnabled']['cloudprintproxyenabled']) == 0):
        Stat16 = "No need to change Control: CloudPrintProxyEnabled \n"
        count = count + 1
                                                            
    else:
        Stat16 = "Setting 'CloudPrintProxyEnabled' requires change: 2.12 (L1) Ensure 'Enable Google Cloud Print Proxy' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['SitePerProcess']['siteperprocess']) == 1):
        Stat17 = "No need to change Control: SitePerProcess \n"
        count = count + 1
                                                                
    else:
        Stat17 = "Setting 'SitePerProcess' requires change: 2.13 (L1) Ensure 'Enable Site Isolation for every site' is set to 'Enabled' \n"
        count2 = count2 + 1    
        
    if(int(config['DownloadRestrictions']['downloadrestrictions']) >= 1):
        Stat18 = "No need to change Control: DownloadRestrictions \n"
        count = count + 1
                                                                    
    else:
        Stat18 = "Setting 'DownloadRestrictions' requires change: 2.14 (L1) Ensure 'Allow download restrictions' is set to 'Enabled' with 'Block dangerous downloads' specified \n"
        count2 = count2 + 1 
        
    if(int(config['disablesafebrowsing']['disablesafebrowsingproceedanyway']) == 1):
        Stat19 = "No need to change Control: DisableSafeBrowsingProceedAnyway \n"
        count = count + 1
                                                                        
    else:
        Stat19 = "Setting 'DisableSafeBrowsingProceedAnyway' requires change: 2.15 (L1) Ensure 'Disable proceeding from the Safe Browsing warning page' is set to 'Enabled' \n"
        count2 = count2 + 1  
        
    if(int(config['RelaunchNotification']['relaunchnotification']) >= 1):
        Stat20 = "No need to change Control: RelaunchNotification \n"
        count = count + 1
                                                                            
    else:
        Stat20 = "Setting 'RelaunchNotification' requires change: 2.16 (L1) Ensure 'Notify a user that a browser relaunch or device restart is recommended or required' is set to 'Enabled' with 'Show a recurring prompt to the user indication that a relaunch is required' specified \n"
        count2 = count2 + 1 
        
    if(int(config['RelaunchNotificationPeriod']['relaunchnotificationperiod']) >= 86400000):
        Stat21 = "No need to change Control: RelaunchNotificationPeriod \n"
        count = count + 1
                                                                                
    else:
        Stat21 = "Setting 'RelaunchNotificationPeriod' requires change: 2.17 (L1) Ensure 'Set the time period for update notifications' is set to 'Enabled' with '86400000' (1 day) specified \n"
        count2 = count2 + 1  
        
    if(int(config['revocationchecklocalanchor']['requireonlinerevocationchecksforlocalanchors']) == 1):
        Stat22 = "No need to change Control: RequireOnlineRevocationChecksForLocalAnchors \n"
        count = count + 1
                                                                                    
    else:
        Stat22 = "Setting 'RequireOnlineRevocationChecksForLocalAnchors' requires change: 2.18 (L2) Ensure 'Whether online OCSP/CRL checks are required for local trust anchors' is set to 'Enabled' \n"
        count2 = count2 + 1
        
    if(int(config['ChromeCleanupEnabled']['chromecleanupenabled']) >= 0):
        Stat23 = "No need to change Control: ChromeCleanupEnabled \n"
        count = count + 1
                                                                                        
    else:
        Stat23 = "Setting 'ChromeCleanupEnabled' requires change: 2.19 (L1) Ensure 'Enable Chrome Cleanup on Windows' is Configured \n"
        count2 = count2 + 1   
        
    if(int(config['BuiltInDnsClientEnabled']['builtindnsclientenabled']) == 0):
        Stat24 = "No need to change Control: BuiltInDnsClientEnabled \n"
        count = count + 1
                                                                                            
    else:
        Stat24 = "Setting 'BuiltInDnsClientEnabled' requires change: 2.20 (L2) Ensure 'Use built-in DNS client' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['DefaultCookiesSetting']['defaultcookiessetting']) == 1):
        Stat25 = "No need to change Control: DefaultCookiesSetting \n"
        count = count + 1
                                                                                                
    else:
        Stat25 = "Setting 'DefaultCookiesSetting' requires change: 3.1 (L2) Ensure 'Default cookies setting' is set to 'Enabled' (Keep cookies for the duration of the session) \n"
        count2 = count2 + 1 
        
    if(int(config['DefaultGeolocationSetting']['defaultgeolocationsetting']) >= 1):
        Stat26 = "No need to change Control: DefaultGeolocationSetting \n"
        count = count + 1
                                                                                                    
    else:
        Stat26 = "Setting 'DefaultGeolocationSetting' requires change: 3.2 (L1) Ensure 'Default geolocation setting' is set to 'Enabled' with 'Do not allow any site to track the users' physical location' \n"
        count2 = count2 + 1 
        
    if(int(config['EnableMediaRouter']['enablemediarouter']) == 0):
        Stat27 = "No need to change Control: EnableMediaRouter \n"
        count = count + 1
                                                                                                        
    else:
        Stat27 = "Setting 'EnableMediaRouter' requires change: 3.3 (L1) Ensure 'Enable Google Cast' is set to 'Disabled' \n"
        count2 = count2 + 1   
        
    if(int(config['BlockThirdPartyCookies']['blockthirdpartycookies']) == 1):
        Stat28 = "No need to change Control: BlockThirdPartyCookies \n"
        count = count + 1
                                                                                                            
    else:
        Stat28 = "Setting 'BlockThirdPartyCookies' requires change: 3.4 (L1) Ensure 'Block third party cookies' is set to 'Enabled' \n"
        count2 = count2 + 1 
        
    if(int(config['MetricsReportingEnabled']['metricsreportingenabled']) == 0):
        Stat29 = "No need to change Control: MetricsReportingEnabled \n"
        count = count + 1
                                                                                                                
    else:
        Stat29 = "Setting 'MetricsReportingEnabled' requires change: 3.5 (L1) Ensure 'Enable reporting of usage and crash-related data' is set to 'Disabled' \n"
        count2 = count2 + 1   
        
    if(int(config['chromecleanupreport']['chromecleanupreportingenabled']) == 0):
        Stat30 = "No need to change Control: ChromeCleanupReportingEnabled \n"
        count = count + 1
                                                                                                                    
    else:
        Stat30 = "Setting 'ChromeCleanupReportingEnabled' requires change: 3.6 (L1) Ensure 'Control how Chrome Cleanup reports data to Google' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['BrowserSignin']['browsersignin']) >= 1):
        Stat31 = "No need to change Control: BrowserSignin \n"
        count = count + 1
                                                                                                                        
    else:
        Stat31 = "Setting 'BrowserSignin' requires change: 3.7 (L1) Ensure 'Browser sign in settings' is set to 'Enabled' with 'Disabled browser sign-in' specified \n"
        count2 = count2 + 1 
        
    if(int(config['TranslateEnabled']['translateenabled']) == 0):
        Stat32 = "No need to change Control: TranslateEnabled \n"
        count = count + 1
                                                                                                                            
    else:
        Stat32 = "Setting 'TranslateEnabled' requires change: 3.8 (L1) Ensure 'Enable Translate' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['NetworkPredictionOptions']['networkpredictionoptions']) >= 1):
        Stat33 = "No need to change Control: NetworkPredictionOptions \n"
        count = count + 1
                                                                                                                                
    else:
        Stat33 = "Setting 'NetworkPredictionOptions' requires change: 3.9 (L1) Ensure 'Enable network prediction' is set to 'Enabled' with 'Do not predict actions on any network connection' selected \n"
        count2 = count2 + 1 
        
    if(int(config['SearchSuggestEnabled']['searchsuggestenabled']) == 0):
        Stat34 = "No need to change Control: SearchSuggestEnabled \n"
        count = count + 1
                                                                                                                                    
    else:
        Stat34 = "Setting 'SearchSuggestEnabled' requires change: 3.10 (L1) Ensure 'Enable search suggestions' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['SpellCheckServiceEnabled']['spellcheckserviceenabled']) == 0):
        Stat35 = "No need to change Control: SpellCheckServiceEnabled \n"
        count = count + 1
                                                                                                                                        
    else:
        Stat35 = "Setting 'SpellCheckServiceEnabled' requires change: 3.11 (L1) Ensure 'Enable or disable spell checking web service' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['AlternateErrorPagesEnabled']['alternateerrorpagesenabled']) == 0):
        Stat36 = "No need to change Control: AlternateErrorPagesEnabled \n"
        count = count + 1
                                                                                                                                            
    else:
        Stat36 = "Setting 'AlternateErrorPagesEnabled' requires change: 3.12 (L1) Ensure 'Enable alternate error pages' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['SyncDisabled']['syncdisabled']) == 1):
        Stat37 = "No need to change Control: SyncDisabled \n"
        count = count + 1
                                                                                                                                                
    else:
        Stat37 = "Setting 'SyncDisabled' requires change: 3.13 (L1) Ensure 'Disable synchronization of data with Google' is set to 'Enabled' \n"
        count2 = count2 + 1    
        
    if(int(config['safebrowsingtrustedsource']['safebrowsingfortrustedsourcesenabled']) == 0):
        Stat38 = "No need to change Control: SafeBrowsingForTrustedSourcesEnabled \n"
        count = count + 1
                                                                                                                                                    
    else:
        Stat38 = "Setting 'SafeBrowsingForTrustedSourcesEnabled' requires change: 3.14 (L1) Ensure 'Enable Safe Browsing for trusted sources' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['urlkeyeddatacollect']['urlkeyedanonymizeddatacollectionenabled']) == 0):
        Stat39 = "No need to change Control: UrlKeyedAnonymizedDataCollectionEnabled \n"
        count = count + 1
                                                                                                                                                        
    else:
        Stat39 = "Setting 'UrlKeyedAnonymizedDataCollectionEnabled' requires change: 3.15 (L1) Ensure 'Enable URL-keyed anonymized data collection' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['allowdeletebrowserhistory']['allowdeletingbrowserhistory']) == 0):
        Stat40 = "No need to change Control: AllowDeletingBrowserHistory \n"
        count = count + 1
                                                                                                                                                            
    else:
        Stat40 = "Setting 'AllowDeletingBrowserHistory' requires change: 3.16 (L1) Ensure 'Enable deleting browser and download history' is set to 'Disabled' \n"
        count2 = count2 + 1
        
    if(int(config['remoteaccessfirewalltraverse']['remoteaccesshostfirewalltraversal']) == 0):
        Stat41 = "No need to change Control: RemoteAccessHostFirewallTraversal \n"
        count = count + 1
                                                                                                                                                                
    else:
        Stat41 = "Setting 'RemoteAccessHostFirewallTraversal' requires change: 4.1.1 (L1) Ensure 'Enable firewall traversal from remote access host' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['remoteaccessclientpair']['remoteaccesshostallowclientpairing']) == 0):
        Stat42 = "No need to change Control: RemoteAccessHostAllowClientPairing \n"
        count = count + 1
                                                                                                                                                                    
    else:
        Stat42 = "Setting 'RemoteAccessHostAllowClientPairing' requires change: 4.1.2 (L1) Ensure 'Enable or disable PIN-less authentication for remote access hosts' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['remoteaccessrelayconnect']['remoteaccesshostallowrelayedconnection']) == 0):
        Stat43 = "No need to change Control: RemoteAccessHostAllowRelayedConnection \n"
        count = count + 1
                                                                                                                                                                        
    else:
        Stat43 = "Setting 'RemoteAccessHostAllowRelayedConnection' requires change: 4.1.3 (L1) Ensure 'Enable the use of relay servers by the remote access host' is set to 'Disabled' \n"
        count2 = count2 + 1
        
    if(int(config['CloudPrintSubmitEnabled']['cloudprintsubmitenabled']) == 0):
        Stat44 = "No need to change Control: CloudPrintSubmitEnabled \n"
        count = count + 1
                                                                                                                                                                            
    else:
        Stat44 = "Setting 'CloudPrintSubmitEnabled' requires change: 5.1 (L1) Ensure 'Enable submission of documents to Google Cloud print' is set to 'Disabled' \n"
        count2 = count2 + 1 
        
    if(int(config['ImportSavedPasswords']['importsavedpasswords']) == 0):
        Stat45 = "No need to change Control: ImportSavedPasswords \n"
        count = count + 1
                                                                                                                                                                                
    else:
        Stat45 = "Setting 'ImportSavedPasswords' requires change: 5.2 (L1) Ensure 'Import saved passwords from default browser on first run' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['AutofillCreditCardEnabled']['autofillcreditcardenabled']) == 0):
        Stat46 = "No need to change Control: AutofillCreditCardEnabled \n"
        count = count + 1
                                                                                                                                                                                    
    else:
        Stat46 = "Setting 'AutofillCreditCardEnabled' requires change: 5.3 (L1) Ensure 'Enable AutoFill for credit cards' is set to 'Disabled' \n"
        count2 = count2 + 1  
        
    if(int(config['AutofillAddressEnabled']['autofilladdressenabled']) == 0):
        Stat47 = "No need to change Control: AutofillAddressEnabled \n"
        count = count + 1
                                                                                                                                                                                        
    else:
        Stat47 = "Setting 'AutofillAddressEnabled' requires change: 5.4 (L1) Ensure 'Enable AutoFill for addresses' is set to 'Disabled' \n"
        count2 = count2 + 1    
       
        
    #print(config.sections())
    print("\n")
    print("============================================================== \n")     
    

    listbox3.insert(0, "Writing to " + timestr + " in program folder.")
    listbox3.insert(1, " ")
    listbox3.insert(2, "Browser Security + Remediations")
    listbox3.insert(3, " ")
    listbox3.insert(4, Stat1)
    listbox3.insert(4, Stat2)
    listbox3.insert(4, Stat3)
    listbox3.insert(4, Stat4)
    listbox3.insert(4, Stat5)
    listbox3.insert(4, Stat6)
    listbox3.insert(4, Stat7)
    listbox3.insert(4, Stat8)
    listbox3.insert(4, Stat9)
    listbox3.insert(4, Stat10)
    listbox3.insert(4, Stat11)
    listbox3.insert(4, Stat12)
    listbox3.insert(4, Stat13)
    listbox3.insert(4, Stat14)
    listbox3.insert(4, Stat15)
    listbox3.insert(4, Stat16)
    listbox3.insert(4, Stat17)
    listbox3.insert(4, Stat18)
    listbox3.insert(4, Stat19)
    listbox3.insert(4, Stat20)
    listbox3.insert(4, Stat21)
    listbox3.insert(4, Stat22)
    listbox3.insert(4, Stat23)
    listbox3.insert(4, Stat24)
    listbox3.insert(4, Stat25)
    listbox3.insert(4, Stat26)
    listbox3.insert(4, Stat27)
    listbox3.insert(4, Stat28)
    listbox3.insert(4, Stat29)
    listbox3.insert(4, Stat30)
    listbox3.insert(4, Stat31)
    listbox3.insert(4, Stat32)
    listbox3.insert(4, Stat33)
    listbox3.insert(4, Stat34)
    listbox3.insert(4, Stat35)
    listbox3.insert(4, Stat36)
    listbox3.insert(4, Stat37)
    listbox3.insert(4, Stat38)
    listbox3.insert(4, Stat39)
    listbox3.insert(4, Stat40)
    listbox3.insert(4, Stat41)
    listbox3.insert(4, Stat42)
    listbox3.insert(4, Stat43)
    listbox3.insert(4, Stat44)
    listbox3.insert(4, Stat45)
    listbox3.insert(4, Stat46)
    listbox3.insert(4, Stat47)
    
    
    
    listbox4.insert(0, "\nNumber of Compliant controls") 
    listbox4.insert(1, "--> " + str(count)) 
    listbox4.insert(2, "Number of Non-Compliant controls") 
    listbox4.insert(3, "--> " + str(count2))
     
# ==== GUI ====
gui = Tk()
gui.title('IT Risk Audit Baseline Analyzer')
gui.geometry("1200x500+20+20")

tabControl = ttk.Notebook(gui)
  
tab1 = ttk.Frame(tabControl)
tab2 = ttk.Frame(tabControl)
  
tabControl.add(tab1, text ='Windows 10/Server')
tabControl.add(tab2, text ='Browsers')
tabControl.pack(expand = 1, fill ="both")
  
# ==== Colors ====
m1c = '#00ee00'
bgc = '#222222'
dbg = '#000000'
fgc = '#111111'

gui.tk_setPalette(background="white", foreground="Black",)

# ==== Labels ====
L11 = Label(tab1, text = "Windows Audit",  font=("Helvetica", 16, 'underline', 'bold'))
L11.place(x = 16, y = 10)

textinput1 = Label(tab1, text="Target IP:")
textinput1.place (x = 220, y = 15)

textinput2 = Label(tab1, text="Target domain:")
textinput2.place (x = 460, y = 15)

textinput3 = Label(tab1, text="Target User:")
textinput3.place (x = 220, y = 45)

textinput4 = Label(tab1, text="User Password:")
textinput4.place (x = 460, y = 45)

L26 = Label(tab1, text = "Results: ")
L26.place(x = 16, y = 60)
L27 = Label(tab1, text = "[ ... ]")
L27.place(x = 80, y = 60)

L11 = Label(tab2, text = "Win-Browser Audit",  font=("Helvetica", 16, 'underline', 'bold'))
L11.place(x = 16, y = 10)

textinput5 = Label(tab2, text="Target IP:")
textinput5.place (x = 220, y = 15)

textinput6 = Label(tab2, text="Target domain:")
textinput6.place (x = 460, y = 15)

textinput7 = Label(tab2, text="Target User:")
textinput7.place (x = 220, y = 45)

textinput8 = Label(tab2, text="User Password:")
textinput8.place (x = 460, y = 45)

L26 = Label(tab2, text = "Results: ")
L26.place(x = 16, y = 60)
L27 = Label(tab2, text = "[ ... ]")
L27.place(x = 80, y = 60)


# ==== Buttons / Scans ====
L26 = Label(tab1, text = "Scan Options:", font=("Helvetica", 16, 'underline', 'bold'))
L26.place(x = 16, y = 220)

IP = Entry(tab1)
IP.place(x = 280, y = 15)

Domain = Entry(tab1)
Domain.place(x = 550, y = 15)

username = Entry(tab1)
username.place(x = 290, y = 45)

passwd = Entry(tab1, show = '*')
passwd.place(x = 550, y = 45)

B11 = Button(tab1, text = "Basic Scan", command=basic, fg='black')
B11.place(x = 16, y = 270, width = 150, height = 40)

B12 = Button(tab1, text = "Intermediate Scan", command=startScan_Intermediate, fg='black')
B12.place(x = 16, y = 340, width = 150, height = 40)

B21 = Button(tab1, text = "Save Result", command=saveScan, fg='black')
B21.place(x = 200, y = 260, width = 200, height=65)

B21 = Button(tab1, text = "Clear Result", command=deleteScan, fg='black')
B21.place(x = 200, y = 330, width = 200, height=65)

L26 = Label(tab2, text = "Scan Options:", font=("Helvetica", 16, 'underline', 'bold'))
L26.place(x = 16, y = 220)

IP2 = Entry(tab2)
IP2.place(x = 280, y = 15)

Domain2 = Entry(tab2)
Domain2.place(x = 550, y = 15)

username2 = Entry(tab2)
username2.place(x = 290, y = 45)

passwd2 = Entry(tab2, show = '*')
passwd2.place(x = 550, y = 45)

B11 = Button(tab2, text = "Google Chrome Scan", command=googlescan, fg='black')
B11.place(x = 16, y = 270, width = 150, height = 40)

B21 = Button(tab2, text = "Save Result", command=saveScan2, fg='black')
B21.place(x = 200, y = 260, width = 200, height=65)

B21 = Button(tab2, text = "Clear Result", command=deleteScan2, fg='black')
B21.place(x = 200, y = 330, width = 200, height=65)




# ==== Result list ====
frame = Frame(tab1)
frame.place(x = 10, y = 100, width = 1100, height = 100)
listbox = Listbox(frame, width = 1100, height = 6)
listbox.place(x = 0, y = 0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

L1 = Label(tab1, text = "Summary of results:", font=("Helvetica", 16, 'underline', 'bold'))
L1.place(x = 430, y = 250)

frame = Frame(tab1)
frame.place(x = 430, y = 295, width = 260, height = 100)
listbox2 = Listbox(frame, width = 100, height = 8)
listbox2.place(x = 0, y = 0)
listbox2.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox2.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

frame = Frame(tab2)
frame.place(x = 10, y = 100, width = 1100, height = 100)
listbox3 = Listbox(frame, width = 1100, height = 6)
listbox3.place(x = 0, y = 0)
listbox3.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox3.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

L1 = Label(tab2, text = "Summary of results:", font=("Helvetica", 16, 'underline', 'bold'))
L1.place(x = 430, y = 250)

frame = Frame(tab2)
frame.place(x = 430, y = 295, width = 260, height = 100)
listbox4 = Listbox(frame, width = 100, height = 8)
listbox4.place(x = 0, y = 0)
listbox4.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox4.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)


# ==== Start GUI ====
gui.mainloop()
