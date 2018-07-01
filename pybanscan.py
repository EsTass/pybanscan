#!/bin/python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Documentation, License etc.

EsTass 2018 
https://github.com/EsTass/

@package pybanscan
'''


#IMPORTS
import sys
import os
import unicodedata
import ntpath
import re
import datetime
import time
import array
import subprocess
import json
import unicodedata
import csv
import pickle
import configparser
import traceback

#CONFIGS
VERSION='0.6'
#VERBOSE MODE -v
G_VERBOSE=True
#VERBOSE MODE DEBUG -vd
G_DEBUG=False
#PRINT NOW DATA -pd
G_WARNINGS_ECHO=False
#log file format: datetime,title,ip,line -fl
G_LOGFILE='./pybanscan.pkl'
#check only this title
G_CTITLE_CHECK=False
#Excluded IPs
G_IPEXCLUDE=[ 
    '0.0.0.0', 
    '192.168.1.1',
    '127.0.0.1',
    ]

#OPTIONS
MSG_OPTIONS = '''
USAGE
pybanscan.py [options]

OPTIONS

 -h : help
 -v : verbose mode
 -vd : verbose debug mode
 -flog "./pybanscan.pkl" : log file with pickle warning data
 -t 5 : time to wait for check in minutes
 -c : check only one time and exit
 -ct "title" : check only title and exit
 -fc "./config.ini" : file config ini format
 -fccreate "./config.ini" : create example config file
 -fctest "./config.ini" : check config file
 -pd : show actual warnings data
 #With port (Default)
 -cmdban "iptables -I INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -I INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for ban action
 -cmdunban "iptables -D INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -D INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for unban action
 -cmdcheckban "iptables -C INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -C INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for check exist action
 #Without port
 -cmdban "iptables -I INPUT -s %IP% -j DROP" : cmd for ban action NO PORT
 -cmdunban "iptables -D INPUT -s %IP% -j DROP" : cmd for unban action NO PORT
 -cmdcheckban "iptables -C INPUT -s %IP% -j DROP" : cmd for check exist action NO PORT
 -ipexclude "0.0.0.0,127.0.0.1,192.168.1.1"
 -ipexcludef "./excips.txt"

CONFIG. Ini file format with each title

[title]
active=False
logcmd=cat /var/log/file
logcmd_line_split=\\n|empty
grepdatetime=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{4})
grepdateformat=%Y-%m-%dT%H:%M:%S%z
grepip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
grepactions=(Invalid\ user|Failed\ Password|Bad\ protocol|attack)
grepactionsignore=session\ open|session\ clos|pam_unix|pam_systemd|Accepted)
bantime=24
banchecks=3
bancheckstime=60
banport=22
 
'''
MSG_APPINFO='pybanscan v'+VERSION+' 2018 https://github.com/EsTass/'

#CONFIGS EDITABLE

#check only 1 time -c
G_CHECKONLYONE=False
#check each X minutes -t 5
G_TIMECHECKS=5
#DateTime Compare
G_LASTCHECK=datetime.datetime.now() - datetime.timedelta(days=1)
#cmd ban %IP% %PORT%
G_BANIP_CMD='iptables -I INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -I INPUT -p udp -s %IP% --dport %PORT% -j DROP && echo "BAN %IP% :: %PORT%" >> ./pybanscan.log'
#G_BANIP_CMD='iptables -I INPUT -s %IP% -j DROP && echo "BAN %IP% :: %PORT%" >> ./pybanscan.log'
#G_BANIP_CMD='echo "BAN %IP% :: %PORT%" >> ./pybanscan.log'
#cmd unban %IP% %PORT%
G_UNBANIP_CMD='iptables -D INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -D INPUT -p udp -s %IP% --dport %PORT% -j DROP && echo "UNBAN %IP% :: %PORT%" >> ./pybanscan.log'
#G_UNBANIP_CMD='iptables -D INPUT -s %IP% -j DROP && echo "UNBAN %IP% :: %PORT%" >> ./pybanscan.log'
#G_UNBANIP_CMD='echo "UNBAN %IP% :: %PORT%" >> ./pybanscan.log'
G_CHECKBANIP_CMD='iptables -C INPUT -p tcp -s %IP% --dport %PORT% -j DROP'
#G_CHECKBANIP_CMD='iptables -C INPUT -s %IP% -j DROP'
#gconfigs title for bans
G_CONFIGS_BANSTITLE='BAN'
#config default example
#check configs -fc "fileconfig"
G_CONFIGS_FILE = './config.ini'
G_CONFIGS={}
G_CONFIGS_EXAMPLE={
        'title' : {
            'active' : False,
            'logcmd' : '',
            'logcmd_line_split' : b'\\n',
            'grepdatetime' : b'',
            'grepdateformat' : b'',
            'grepip' : b'',
            'grepactions' : b'',
            'grepactionsignore' : b'',
            'bantime' : 24,
            'banchecks' : 3,
            'bancheckstime' : 60,
            'banport' : 22,
            },
        'sshd_login_fails' : {
            'active' : False,
            'logcmd' : 'journalctl --no-pager -n 1000 -o short-iso -q -u sshd --since="%SINCE%"',
            'logcmd_line_split' : b'\\n',
            'grepdatetime' : b'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{4})',
            'grepdateformat' : '%Y-%m-%dT%H:%M:%S%z',
            'grepip' : b'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'grepactions' : b'(Invalid\ user|Failed\ Password|Bad\ protocol|attack)',
            'grepactionsignore' : b'(session\ open|session\ clos|pam_unix|pam_systemd|Accepted)',
            'bantime' : 24,
            'banchecks' : 3,
            'bancheckstime' : G_TIMECHECKS,
            'banport' : 22,
            },
        'apache_bots' : {
            'active' : False,
            'logcmd' : 'tail -n 1000 /var/log/httpd/access_log',
            'logcmd_line_split' : b"\\n",
            'grepdatetime' : b'(\d{2}/\w{2,3}/\d{4}:\d{2}:\d{2}:\d{2}..\d{4})',
            'grepdateformat' : '%d/%b/%Y:%H:%M:%S %z',
            'grepip' : b'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'grepactions' : b'(muieblackcat|mysqladmin|phpMyAdmin|check_proxy|a2billing|wls-wsat|attack)',
            'grepactionsignore' : b'(\:\:1|127\.0\.0\.1)',
            'bantime' : 24,
            'banchecks' : 3,
            'bancheckstime' : G_TIMECHECKS,
            'banport' : 443,
            },
        'apache_invalid' : {
            'active' : True,
            'logcmd' : 'tail -n 1000 /var/log/httpd/access_log',
            'logcmd_line_split' : b'\\n',
            'grepdatetime' : b'(\d{2}/\w{2,3}/\d{4}:\d{2}:\d{2}:\d{2}..\d{4})',
            'grepdateformat' : '%d/%b/%Y:%H:%M:%S %z',
            'grepip' : b'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'grepactions' : b'(invalid user)',
            'grepactionsignore' : b'(\:\:1|127\.0\.0\.1)',
            'bantime' : 24,
            'banchecks' : 3,
            'bancheckstime' : G_TIMECHECKS,
            'banport' : 443,
            },
    }


#FUNCTIONS

#GET PARAMS

def getParam( param ):
    result=False
    
    #PARAMS
    ARG = sys.argv
    ARG = list(map(os.fsencode, sys.argv))
    printEDebug( 'Number of arguments:', len(sys.argv), 'arguments.' )
    printEDebug( 'Argument List:', str(sys.argv) )
    next=False
    for a in ARG:
        try:
            #, 'surrogateescape'
            b=a.decode('UTF-8', 'surrogateescape')
            b=str(encodeUTF8(b),'UTF-8')
            a=b
        except:
            pass
        printEDebug( 'Check ARG:', a )
        if next:
            result=a
            break
        elif a == param:
            printEDebug( '+ARG:', str(a),param )
            result=a.replace(param,'')
            result=u''
            next=True
    
    return result

#INI FILE CONFIG

def loadConfig(file):
    result={}
    cdata={}
    ctitle=''
    
    if os.path.isfile( file ):
        with open(file) as fin:
            for line in fin:
                line=line.strip('\n')
                if len(line) == 0:
                    #comment
                    printEDebug('::CFILE EMPTY:', line)
                elif line.startswith('#'):
                    #comment
                    printEDebug('::CFILE COMMENT:', line)
                elif line.startswith('['):
                    #base element
                    printEDebug('::CFILE TITLE:', line)
                    ctitle=line.replace('[','',1)
                    ctitle=ctitle.replace(']','', 1)
                    cdata[ctitle]={}
                else:
                    #data element
                    td=line.split('=',1)
                    if len(td)==2:
                        printEDebug('::CFILE TITLE VALUE:', ctitle, td[0], td[1])
                        #check type
                        try:
                            vd=td[1].strip()
                            if vd=='False' or vd=='0':
                                vd=False
                            elif vd=='True' or vd=='1':
                                vd=True
                            elif vd.isalnum():
                                vd=float(vd)
                            else:
                                vd=encodeUTF8(vd)
                            cdata[ctitle][td[0]]=vd
                        except:
                            printE('::CFILE ERROR PARSING VALUES:',line, ctitle, td[0], td[1])
                            sys.exit(0)
                    else:
                        printE('::CFILE ERROR PARSING VALUE:',line)
                        sys.exit(0)
                
        if len(cdata)>0:
            printE('::Config loaded:', file)
            result = cdata
        else:
            printE('::Config loaded ERROR:', file)
    
    return result

def checkConfig(data):
    result=False
    
    for title,row in data.items():
        printE('::Config CHECKTITLE:', title)
        for rtitle, rvalue in row.items():
            printE('::::Config VALUE:', rtitle, rvalue)
        
        
    return result

def createConfigExample( file ):
    global G_CONFIGS_EXAMPLE
    result=False
    
    try:
        with open(file, 'w', encoding='utf-8') as fp:
            for key,row in G_CONFIGS_EXAMPLE.items():
                fp.write('{}'.format(os.linesep))
                fp.write('[{}]{}'.format(key, os.linesep))
                for rkey,rrow in row.items():
                    fp.write('{}={}{}'.format(encodeSTR(rkey),encodeSTR(rrow), os.linesep))
            fp.close()
            result=True
    except:
        result=False
        
    return result

#CHECK CONFIGS DATA

def checkConfigs( pdata, title, data ):
    global G_TIMECHECKS
    global G_IPEXCLUDE
    result=False
    linesreport = []
    
    if data[ 'active' ]==False:
        printE( '::Disabled:', title )
    else:
        printEDebug( '::CMD:', data[ 'logcmd' ] )
        #since
        tcmd=data[ 'logcmd' ]
        since=datetime.datetime.now() - datetime.timedelta(minutes=data['bancheckstime'])
        since=encodeUTF8(str(since))
        tcmd=tcmd.replace(b'%SINCE%',since)
        datacmd=cmd(tcmd)
        if len(data[ 'logcmd_line_split' ]) > 0:
            lines=datacmd.split( data[ 'logcmd_line_split' ] )
        else:
            lines=datacmd.splitlines()
        printE('::CMD Lines: ', len(lines))
        for line in lines:
            if len(line)>0:
                printEDebug('')
                printEDebug('::Line: ', line)
                CONTINUE=True
            else:
                CONTINUE=False
            #get time
            if CONTINUE:
                ldate=encodeSTR(extractDateTime(line,data[ 'grepdatetime' ]))
                printEDebug('::CMD Date: ', ldate)
                #conver time
                ldt=False
                try:
                    #grepdateformat
                    ldt=datetime.datetime.strptime(ldate,encodeSTR(data['grepdateformat'])).replace(tzinfo=None)
                except:
                    ldt=False
                    CONTINUE=False
                    pass
                #check in time
                if ldt == False:
                    printEDebug('::No valid date: ',ldt,ldate)
                elif( ldt < G_LASTCHECK ):
                    printEDebug('::DateTime prechecked: ',ldt,ldate)
                else:
                    printEDebug('::Line in Time: ',ldt,ldate)
                    CONTINUE=True
            
            #Check IP
            if CONTINUE:
                IP=checkIP(line,data['grepip'])
                if IP == False \
                or IP in G_IPEXCLUDE:
                    printEDebug('--IP exclude: ', IP)
                    CONTINUE=False
            #Check exclude
            if CONTINUE:
                if len(data['grepactionsignore']) > 0 and \
                checkRE(line,data['grepactionsignore']):
                    printEDebug('--Line exclude: ',)
                    CONTINUE=False
            #Check include
            if CONTINUE:
                if  len(data['grepactions']) > 0 and \
                checkRE(line,data['grepactions']):
                    printEDebug('++Line REPORT: ', line)
                    linesreport.append(line)
                    pdata=setIPWarning(pdata, ldt,title,IP,line)
                    CONTINUE=False    
        printEDebug('##LINES REPORTED:', linesreport)
        printE('##LINES REPORTED:', len(linesreport))
    
    result=pdata
    return result

#ACTIONS LOGFILE
'''
    dict: {
        title: {  
            datetime : [ ip, line ],
            ...
        },
        ...
        BANS: {  
            title : { 
                ip : datetime,
                ...
            },
            ...
        }
    }
'''

def openWarnings( file ):
    result={}
    
    if os.path.isfile(file):
        result = pickle.load( open( file, "rb" ) )
    
    return result

def saveWarnings( file, data ):
    result = pickle.dump( data, open( file, "wb" ) )
    return result

def setIPWarning(data,datetime,title,ip,line):
    printEDebug('::IPWARNING SET:', title, ip, line)
    printEDebug('::IPWARNING NOW:', data)
    title=encodeSTR(title)
    datetime=encodeSTR(datetime)
    if title not in data.keys():
        data[title]={}
    if datetime not in data[title].keys():
        data[title][datetime]=[]
    
    data[title][datetime]=[
        encodeSTR(ip),
        encodeSTR(line)
    ]
    
    return data

#{ ip: warnings }
def getIPWarnings( data, title, timecheck ):
    global G_LOGFILE
    result = {}
    vdates=[]
    
    if title in data.keys():
        for rdtime,row in data[title].items():
            printEDebug('::BANS ROW LOADED: ', rdtime, row)
            try:
                ldate=datetime.datetime.strptime(str(rdtime),'%Y-%m-%d %H:%M:%S')
                printEDebug('::BANS ROW DATE: ', ldate)
            except:
                ldate=False
            if ldate and \
            ldate > timecheck:
                printEDebug('::BANS ROW IP: ', row[0])
                if row[0] in result.keys():
                    result[row[0]]=(result[row[0]]+1)
                else:
                    result[row[0]]=1
                printEDebug('::BANS ROW IP COUNT: ', result[row[0]])
            
    return result

#[ip,...]
def getIPUnbans( data, title, timecheck ):
    global G_CONFIGS_BANSTITLE
    result = []
    
    if G_CONFIGS_BANSTITLE in data.keys() \
    and title in data[G_CONFIGS_BANSTITLE].keys():
        for ip,rdtime in data[G_CONFIGS_BANSTITLE][title].items():
            printEDebug('::UNBANS ROW LOADED: ', ip, rdtime)
            try:
                ldate=datetime.datetime.strptime(str(rdtime),'%Y-%m-%d %H:%M:%S')
                printEDebug('::UNBANS ROW DATE: ', ldate)
            except:
                ldate=False
            if ldate and \
            ldate > timecheck:
                printEDebug('::UNBANS ROW IP: ', ip)
                result.append(ip)
    
    return result

#data
def removeIPBan( data, title, ip ):
    global G_CONFIGS_BANSTITLE
    result = data
    
    if G_CONFIGS_BANSTITLE in data.keys() \
    and title in data[G_CONFIGS_BANSTITLE].keys() \
    and ip in data[G_CONFIGS_BANSTITLE][title].keys():
        printEDebug('::BANS REMOVE: ', title, ip)
        data[G_CONFIGS_BANSTITLE][title].pop(ip, None)
        result = data
        
    return result

def checkIPBans(data):
    global G_CONFIGS
    result=False
    
    for gtitle,gdata in G_CONFIGS.items():
        if gdata['active']:
            printEDebug('')
            printEDebug('::BANS CHECK: ', gtitle)
            dtcheck=datetime.datetime.now() - datetime.timedelta(minutes=gdata['bancheckstime'])
            printEDebug('::BANS TIME CHECK: ', dtcheck)
            tdata=getIPWarnings(data, gtitle, dtcheck)
            printEDebug('::BANS DATA: ', tdata)
            for ip,quantity in tdata.items():
                printEDebug('::BANS CHECK IP: ', ip, quantity)
                if quantity >= gdata['banchecks']:
                    printE('!!BAN IP: ', ip, quantity)
                    dti=datetime.datetime.now()
                    #BAN CHECK
                    setIPWarning(data,dti,gtitle,ip,u'')
                    checkbancmd=encodeSTR(G_CHECKBANIP_CMD.replace('%IP%',encodeSTR(ip)))
                    checkbancmd=encodeSTR(checkbancmd.replace('%PORT%',encodeSTR(str(int(gdata['banport'])))))
                    #CHECK EXIST
                    if cmdValid( checkbancmd ):
                        #BAN ADD CMD
                        bancmd=encodeSTR(G_BANIP_CMD.replace('%IP%',encodeSTR(ip)))
                        bancmd=encodeSTR(bancmd.replace('%PORT%',encodeSTR(str(int(gdata['banport'])))))
                        r=cmd(bancmd)
                        printEDebug('!!BAN IP CMD RESULT: ', r)
                    else:
                        printEDebug('!!BAN IP EXIST: ', encodeSTR(ip))
    result=data
    return result

def checkIPUnbans(data):
    global G_CONFIGS
    global G_CONFIGS_BANSTITLE
    result=data
    
    for gtitle,gdata in G_CONFIGS.items():
        if gdata['active']:
            printEDebug('')
            printEDebug('::UNBANS CHECK: ', gtitle)
            dtnow=datetime.datetime.now()
            dtcheck=datetime.datetime.now() - (datetime.timedelta(minutes=gdata['bancheckstime']))
            printEDebug('::UNBANS TIME CHECK: ', dtcheck)
            tdata=getIPUnbans(data,gtitle, dtcheck)
            printEDebug('::UNBANS DATA: ', tdata)
            for ip in tdata:
                printE('!!UNBANS IP: ', ip)
                bancmd=encodeSTR(G_UNBANIP_CMD.replace('%IP%',encodeSTR(ip)))
                bancmd=encodeSTR(bancmd.replace('%PORT%',encodeSTR(gdata['banport'])))
                r=cmd(bancmd)
                printEDebug('!!UNBANS IP CMD RESULT: ', r)
                result = data = removeIPBan(data,gtitle,ip)
    
    return result

#CHECK REGEXP

def checkRE( line, format ):
    result=False
    
    #grep
    printEDebug('::GREP: ', format)
    c=re.search(format, line, re.IGNORECASE)
    if c:
        result=True
    
    return result

#CHECK IP

def checkIP( line, format ):
    result=False
    
    #grep
    printEDebug('::GREP IP: ', format)
    c=re.findall(format, line, re.IGNORECASE)
    if c:
        printEDebug('::GREP IP FOUND: ', c[0])
        result=c[0]
    
    return result


#EXTRACT DATE

def extractDateTime( line, format ):
    result=False
    
    #DateFormat
    printEDebug('::GetDate GREP: ', format)
    c=re.findall(format, line, re.IGNORECASE)
    for y in c:
        printEDebug('::GetDate: ', y)
        result=y
        break
    
    return result

#CMD

def cmd( cmd ):
    data=False
    try:
        printEDebug( "::CMD: ", cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err)=p.communicate()
        printEDebug( "Search Output: ", output )
        p_status=p.wait()
        data=output
    except:
        data=False
        pass
    
    return data

def cmdValid( cmd ):
    data=True
    try:
        printEDebug( "::CMDVALID: ", cmd)
        if subprocess.check_call(cmd, shell=True):
            data=True
        else:
            data=False
        printEDebug( "::CMDVALIDCHECK:  ", data )
    except:
        pass
    
    return data

#BASE

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""

    # from whichcraft import which
    from shutil import which

    return which(name) is not None

def printE(msg1, msg2='',msg3='',msg4='',msg5=''):
    """Print if verbose mode G_VERBOSE"""
    global G_VERBOSE
    if G_VERBOSE:
        try:
            a=str(encodeUTF8(msg1),'UTF-8')
            b=str(encodeUTF8(msg2),'UTF-8')
            c=str(encodeUTF8(msg3),'UTF-8')
            d=str(encodeUTF8(msg4),'UTF-8')
            e=str(encodeUTF8(msg5),'UTF-8')
            print(a,b,c,d,e)
        except:
            print(msg1,msg2,msg3,msg4,msg5)

def printEDebug(msg1, msg2='',msg3='',msg4='',msg5=''):
    """Print if verbose mode G_DEBUG"""
    global G_DEBUG
    if G_DEBUG:
        try:
            a=str(encodeUTF8(msg1),'UTF-8')
            b=str(encodeUTF8(msg2),'UTF-8')
            c=str(encodeUTF8(msg3),'UTF-8')
            d=str(encodeUTF8(msg4),'UTF-8')
            e=str(encodeUTF8(msg5),'UTF-8')
            print(a,b,c,d,e)
        except:
            print(msg1,msg2,msg3,msg4,msg5)

def printDict( data, indent=0 ):
    #print("{" + str(os.linesep).join("{}: {}".format(k, v) for k, v in data.items()) + "}")
    #print( json.dumps(data,sort_keys=True, indent=4))
    if isinstance(data, dict):
        for key, value in data.items():
            print('  ' * indent + str(key))
            if isinstance(value, dict) or isinstance(value, list):
                printDict(value, indent+1)
            else:
                print('  ' * (indent+1) + str(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) or isinstance(item, list):
                printDict(item, indent+1)
            else:
                print('  ' * (indent+1) + str(item))
    else:
        pass

def encodeUTF8( s ):
    """Encode UTF8 try"""
    result=s
    if isinstance(s,str) and len(s) > 0:
        try:
            result=s.encode( "utf-8", errors="ignore")
        except:
            pass
    
    return result

def encodeSTR( s ):
    """Encode UTF8 try"""
    result=s
    try:
        a=str(s, "utf-8", errors="ignore")
        result=a
    except:
        pass

    return result

#BASECODE

#PARAMS

#-h
if getParam('-h') != False:
    printE( MSG_OPTIONS )
    printE( '' )
    sys.exit(0)

#-v
p=getParam('-v')
if p != False:
    printE('::Verbose mode')
    G_VERBOSE=True

#-vd
p=getParam('-vd')
if p != False:
    printE('::Verbose DEBUG mode')
    G_DEBUG=True

#-fccreate "FILE"
p=getParam('-fccreate')
if p != False and len(p) > 0:
    p=os.path.abspath(p)
    try:
        p=os.path.abspath(p)
        printE('::Create example config file: ', p)
        createConfigExample(p)
    except:
        printE('::Error creating example file: ', p)
    sys.exit(0)

#-fctest "FILE"
p=getParam('-fctest')
if p != False and len(p) > 0:
    p=os.path.abspath(p)
    G_CONFIGS=loadConfig(p)
    if G_CONFIGS:
        printDict(G_CONFIGS)
    else:
        printE('::Load Config ERROR:', G_CONFIGS)
    sys.exit(0)
    try:
        p=os.path.abspath(p)
        printE('::Test config file: ', p)
        #Load config
        G_CONFIGS=loadConfig(p)
        printDict(G_CONFIGS, 0)
    except:
        printE('::Error config file: ', p)
    sys.exit(0)

#-fc "fileconfig"
p=getParam('-fc')
if p != False and len(p) > 0:
    p=os.path.abspath(p)
    G_CONFIGS_FILE = p
try:
    if os.path.isfile( G_CONFIGS_FILE ):
        printE('::Config FILE: ', G_CONFIGS_FILE)
        #Load config
        G_CONFIGS=loadConfig(G_CONFIGS_FILE)
    else:
        printE('::Config FILE NOT Exist: ', G_CONFIGS_FILE)
except:
    printE('::Config FILE Error: ', G_CONFIGS_FILE)

#-c
p=getParam('-c')
if p != False:
    printE('::Only check mode')
    G_CHECKONLYONE=True

#-t 5 G_TIMECHECKS
p=getParam('-t')
if p != False and len(p) > 0 and p.isdigit():
    G_TIMECHECKS=int(p)
    printE('::Checking Time: ', p, 'minutes')

#-flog './pybanscan.pkl' G_LOGFILE
p=getParam('-flog')
if p != False and len(p) > 0:
    try:
        p=os.path.abspath(p)
        printE('::Log FILE: ', p)
        G_LOGFILE=p
    except:
        printE('::Log File Error: ', p)

#-pd
if getParam('-pd') != False:
    printE( '' )
    printE( '::PRINT WARNINGS DATA' )
    data=openWarnings(G_LOGFILE)
    printDict(data,0)
    sys.exit(0)

#-ipexclude
p=getParam('-ipexclude')
if p != False and len(p) > 0:
    try:
        pe=p.split(',')
        for pee in pe:
            G_IPEXCLUDE.append(pee.strip())
        printE('::Excluded IPs: ', G_IPEXCLUDE)
    except:
        printE('::Excluded IP Error: ', p)

#-ipexcludef "./excips.txt"
p=getParam('-ipexcludef')
if p != False and len(p) > 0:
    try:
        p=os.path.abspath(p)
        printE('::Excluded IPs File: ', p)
        with open(p,'r') as fp:
            line = fp.readline()
            while line:
                G_IPEXCLUDE.append(line.strip())
                line = fp.readline()
            fp.close()
        printE('::Excluded IPs: ', G_IPEXCLUDE)
            
    except:
        printE('::Excluded IPs File Error: ', p)

#-cmdban
p=getParam('-cmdban')
if p != False and len(p) > 0:
    G_BANIP_CMD=p
    printE('::CMD BAN NEW: ', G_BANIP_CMD)

#-cmdunban
p=getParam('-cmdunban')
if p != False and len(p) > 0:
    G_UNBANIP_CMD=p
    printE('::CMD UNBAN NEW: ', G_BANIP_CMD)

#-ct "title" 
p=getParam('-ct')
if p != False and len(p) > 0:
    G_CHECKONLYONE=True
    G_CTITLE_CHECK=p
    printE('::CHECK CONFIG TITLE: ', G_CTITLE_CHECK)

#BASE


#LOAD WARNINGS DATA
printE( '::Load previous data: ', G_LOGFILE )
EDATA=openWarnings(G_LOGFILE)
printE( '::Data loaded: ', len(EDATA) )

ACTIVE=True
while ACTIVE:
    
    #check each G_CONFIGS
    for title, data in G_CONFIGS.items():
        if G_CTITLE_CHECK==False or G_CTITLE_CHECK==title:
            printE( '' )
            printE( '::Checking: ', title, '' )
            EDATA=checkConfigs( EDATA,title, data )
    
    #BAN WITH DATA LOG
    printE( '')
    printE( '::CHECK BANS: ', datetime.datetime.now() )
    EDATA=checkIPBans(EDATA)
    
    #UNBAN WITH DATA LOG
    printE( '')
    printE( '::CHECK UNBANS: ', datetime.datetime.now() )
    EDATA=checkIPUnbans(EDATA)
    
    #SAVE DATA
    printE( '')
    printE( '::SAVE DATA: ', datetime.datetime.now() )
    saveWarnings(G_LOGFILE, EDATA)
    
    printE( '')
    printE( '::END ', datetime.datetime.now() )
    #Waiting Time
    timecheck=( G_TIMECHECKS * 60 )
    printE( '::Waiting ', G_TIMECHECKS, ' mins ...' )
    
    if G_CHECKONLYONE == False:
        try:
            time.sleep( timecheck )
        except KeyboardInterrupt:
            printE( "::Closed." )
            sys.exit()
        
    #recheck last
    G_LASTCHECK=datetime.datetime.now() - datetime.timedelta(minutes=G_TIMECHECKS)
    
    if G_CHECKONLYONE:
        ACTIVE=False
