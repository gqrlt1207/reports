import sys
import os
import time
import autologin
import downloadFile
from pexpect import *
import pexpect
import paramiko
import commands
import smtplib
from smtplib import SMTPException
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email import Encoders
from email.mime.text import MIMEText
import sendEmail
import sendEmailV2
import xlsxwriter
import datetime
import glob
import shutil
import json
import crExcel
import re
#import fileinput
from urllib import urlopen
from pprint import pprint
import analyzeExcel
import formatExcel



if len(sys.argv) < 3:
   print("\n\nUsage: python getIssueInfo.py <last ? hours> <date>\n")
   print("or")
   print("\nUsage: python getIssueInfo.py  <20xx-xx-xx> <how many days back>\n\n")   
   quit()

tmm=sys.argv[1]
tmm2=sys.argv[2]
#print(tmm)

#open("/tmp/hiroQueue.out","w").close()
#hiroFile=open("/tmp/hiroQueue.out","wb+")

def searchSNresult(incId):
  flag="nodata"
  with open("/tmp/snowcheckhistory.out","r") as inputFile:
    for line in inputFile:
      if incId in line:
        sp=[]
        sp=line.split(',')
        flag="nodata"
        flag=sp[1].strip()
        break
  return(flag)

def writeDataToHis(incId,flag):
  with open("/tmp/snowcheckhistory.out","a") as outputFile:
    outputFile.write(incId+' , '+flag+'\n')

def chkJavaScriptErr(incId,note2):
  flag="nodata"
  flag=searchSNresult(incId)
  if "nodata" in flag:
    getT="date +'%s'"
    status,times=commands.getstatusoutput(getT)
    timestamp=int(times)
    value=datetime.datetime.fromtimestamp(timestamp)
    curT=value.strftime('%y-%m-%dT%H:%M:%SZ')
    #print(curT)
    iid="checkJavaScriptError"
    tranId=iid+curT+incId
    testcmd="curl -s -o /tmp/snowcheck.out  -u xxx:xxx \'https://mule-internal.muleca.compucom.com/api/incident/incidentnumber?caseNumber="+incId+"&transactionId="+tranId+"&sender=HIRO&client=OPS&include=Worknotes,Notes\'"
    os.system(testcmd)
    note2=note2.replace("<"," ").replace(">"," ").replace("p"," ").replace("br"," ").replace("table"," ").replace("/"," ").replace("/"," ").replace("tr"," ").replace("td"," ").replace("\\"," ")
    note2=re.sub(' +',' ',note2)
    print("\n"+note2+"\n")
    bb=note2.strip().split(' ')
    bb=bb[:3]
    keyword1=bb[0]
    keyword2=bb[1]
    keyword3=bb[2]

    print("\n keywords:"+keyword1+','+keyword2+','+keyword3+','+"\n")

    output_json = json.load(open('/tmp/snowcheck.out'))
    flag="notFound"
    for k in output_json['incident']['internalNotes']:
      note="nodata"
      note=k['note']
      print("\n"+note+"\n")
      if (keyword1 in note and keyword2 in note and keyword3 in note) or ("INACTIVE" in note):
        flag="Succeeded" 
        break
    print("\n"+flag+"\n")
    writeDataToHis(incId,flag)
  
  return(flag)



def getUnixTime(ctime):
  getCurt="date +'%s'"
  status,times=commands.getstatusoutput(getCurt)
  timestamp=int(times)
  print(timestamp)
  sp=[]
  sp=str(ctime).split(' ')
  date1=sp[0].split('-')
  clock1=sp[1].split(':')
  y1=date1[0]
  m1=date1[1].lstrip('0')
  d1=date1[2].lstrip('0').rstrip()
  h1=clock1[0]
  mm1=clock1[1]
  s1=clock1[2].rstrip().rstrip('\n')
  print("\n"+y1+m1+d1+h1+mm1+s1+"\n")
  dt=datetime.datetime(int(y1),int(m1),int(d1),int(h1),int(mm1),int(s1))
  timeThreshold=4*60*60
  timeDifference=int(timestamp)-int(time.mktime(dt.timetuple()))
  if timeDifference > timeThreshold:
    return("IssueFound")
  else:
    return("noIssue")

#print(getUnixTime("2019-01-09 19:20:03"))
#sys.exit(0)

if "date" in tmm2:
  sTime=""
  eTime=""
  getCurt="date +%s"
  status,curtt=commands.getstatusoutput(getCurt)

  curtt=int(curtt)*1000-3600*int(tmm)*1000
  #print(curtt)

  tStamp=int(curtt)/1000
  #print(tStamp)
  val=datetime.datetime.fromtimestamp(tStamp)
  sTime=val.strftime('%Y-%m-%d %H:%M:%S')
  eTime="date"
  
  getCurt="date +'%s'"
  status,times=commands.getstatusoutput(getCurt)
  timestamp=int(times)
  value=datetime.datetime.fromtimestamp(timestamp)
  curTT=value.strftime('%m%d')
  print(sTime)
  print(eTime)

else:
  sp=[]
  sp=tmm.split('-')
  curTT=sp[1]+sp[2]
  eTime=tmm+" 06:05:00"
  timeTo=time.mktime(datetime.datetime.strptime(eTime, '%Y-%m-%d %H:%M:%S').timetuple())
  timeTo=int(timeTo)
  timeFrom=timeTo-int(tmm2)*3600*24
  val=datetime.datetime.fromtimestamp(timeFrom)
  sTime=val.strftime('%Y-%m-%d %H:%M:%S')
  print(sTime)
  print(eTime)


def searchNode(file,node,words):
  file1=open(file,"rb")
  for line in file1:
    sp=[]
    sp=line.split(",")
    iid=sp[0].strip()
    if "compucom.com" in iid:
      continue
    Basename=sp[1].strip()
    IPAddress=sp[2].strip().rstrip("\n")
    osName=sp[3].strip()
    supportGroup=sp[6].strip()
    ogithost=sp[7].strip()
    ogitfirewall=sp[8].strip().rstrip("\n")
    if words=="IPAddress":
      if node in line and IPAddress!="nodata":
        return(iid,IPAddress)
    elif words=="supportGroup":
      if node in line and supportGroup!="nodata":
        return(iid,supportGroup)     
    elif words=="ogithost":
      if node in line and ogithost!="nodata":
        return(iid,ogithost)
    elif words=="ogitfirewall":
      if node in line and ogitfirewall!="nodata":
        return(iid,ogitfirewall)
  file1.close()
  return(0) 

def getKiList(token,iid):
  kis = []
  testCmd='curl -k -s -o /tmp/kiList.out'+' -X GET -H "_TOKEN:'+token+'" -H "Content-Type: application/json" '+' \'https://ca-graph.hiroca.compucom.com/query/gremlin?query=bothE("ogit/generates").inV()&root='+iid+'\''
  #print(testCmd)
  os.system(testCmd) 
  output_json = json.load(open('/tmp/kiList.out'))
  newKi=""
  for k in output_json['items']:
    newKi=""
    newKi=k['ogit/Automation/knowledgeItemId'] 
    if newKi not in kis:
      kis.append(newKi)
  return(kis)



def chkDupNode(file,node):
  file1=open(file,"rb")
  nCopy=0
  for line in file1:
    sp=[]
    sp=line.split(",")
    iid=sp[0].strip()
    if "compucom.com" in iid:
      continue
    Basename=sp[1].strip()
    if Basename==node and node in iid:
      nCopy +=1
  file1.close()
  return(nCopy)

def chkSnowStatus(inc,iid):
  getT="date +'%s'"
  status,times=commands.getstatusoutput(getT)
  timestamp=int(times)
  value=datetime.datetime.fromtimestamp(timestamp)
  curT=value.strftime('%y-%m-%dT%H:%M:%SZ')
  #print(curT)
  tranId=iid+curT+inc
  qcmd="curl -s -o /tmp/snow.out " + "\'https://xxx:xxx@mule-internal.muleca.compucom.com/api/incident/incidentnumber?sender=HIRO&client=HIRO&transactionId="+tranId+"\&caseNumber="+inc+"\'"
  #print(qcmd)
  try:
    os.system(qcmd)
    output_json = json.load(open('/tmp/snow.out'))
    return(str(output_json['incident']['status']).strip(),str(output_json['incident']['supportGroup']).strip())
  except:
    #if str(output_json['statusCode']) == "404":
    return("nodata","nodata")
    pass

def sIncident(inc,file):
  file1=open(file,'rb+')
  for line in file1:
    if inc in line:
      #print(line)
      return("Found")
      break
  return("notFound")


def chkIncInfo(inc,iid):
  incc=inc
  iidd=iid
  tFound="False"
  snowSta="nodata"
  sGrp="nodata"
  file=open("/tmp/incStatus.out", "r+")
  for line in file:
    if incc in line:
      sp=[]
      sp=line.split(",")
      snowSta=sp[1].strip()
      sGrp=sp[2].strip().rstrip('\n')
      tFound="True"
      break
  file.close()
  if tFound=="True":
    #print(snowSta+' '+sGrp)
    return(snowSta,sGrp) 
  tFound="False"
  file2=open("/tmp/incStatusTemp.out","r+")
  for line in file2:
    if incc in line:
      sp=[]
      sp=line.split(",")
      snowSta=sp[1].strip()
      sGrp=sp[2].strip().rstrip('\n')
      tFound="True"
      break
  file2.close()
  if tFound=="True":
    #print(snowSta+' '+sGrp)
    return(snowSta,sGrp)
  #query Service Now to get the data
  tFound="False"
  file3=open("/tmp/noTicketInSnow.out","r+")
  for line in file3:
    if incc in line:
      tFound="True"
      break
  file3.close()
  if tFound=="True":
    #print(incc+' , '+"nodata"+" , "+" nodata ")    
    return("nodata","nodata")
  snowSta,sGrp=chkSnowStatus(incc,iidd)
  #print(incc+' '+snowSta+' '+sGrp+'\n')
  tFound="False"
  if snowSta=="Closed" or snowSta=="Resolved":
    #tFound=sIncident(incc,"/tmp/incStatus.out","a+")
    #if tFound!="True":
    file1=open("/tmp/incStatus.out","a+")
    file1.write(incc+' , '+snowSta+' , '+sGrp+'\n')
    file1.close()
  elif snowSta!="nodata":
    #tFound=sIncident(incc,"/tmp/incStatusTemp.out")
    #if tFound!="True":
    file2=open("/tmp/incStatusTemp.out","a+")
    file2.write(incc+' , '+snowSta+' , '+sGrp+'\n')
    file2.close()
  elif snowSta=="nodata":
    #tFound=sIncident(incc,"/tmp/noTicketInSnow.out")
    #if tFound!="True":
    for i in range(5):
      snowSta,sGrp=chkSnowStatus(incc,iidd)
      tFound="False"
      if snowSta!="nodata":
        tFound="True"
        break  
    if tFound=="False":
      file3=open("/tmp/noTicketInSnow.out","a+")
      file3.write(incc+' , '+snowSta+' , '+sGrp+'\n')
      file3.close()
    elif snowSta=="Closed" or snowSta=="Resolved":
      file1=open("/tmp/incStatus.out","a+")
      file1.write(incc+' , '+snowSta+' , '+sGrp+'\n')
      file1.close()
    elif snowSta!="nodata":
      file2=open("/tmp/incStatusTemp.out","a+")
      file2.write(incc+' , '+snowSta+' , '+sGrp+'\n')
      file2.close()

  return(snowSta,sGrp)


def sIAMM(incID):
  mExist="False"
  iRec="notCleared"
  clearTime="nodata"
  with open("/tmp/iamm.out","rb+") as inputFile:
    for line in inputFile:
      if incID in line:
        sp=[]
        sp=line.split(",")
        clearTime=sp[2].strip()
        iRec="Cleared"  
        mExist="False"
        return(mExist,iRec,clearTime)
  file8=open("/tmp/issue.tmp2","rb+") 
  ctime2="nodata"
  iamM="nodata"
  eventStatus2="nodata"
  for line in file8:
    eventStatus2="nodata"
    sp1=[]
    sp1=line.split(",")
    ctime2=sp1[1].strip()
    iamM=sp1[9].strip()
    eventStatus2=sp1[5].strip()
    if incID in line and "True" in iamM:
      mExist="True"
    if incID in line and eventStatus2=="INACTIVE" and clearTime=="nodata":
      iRec="Cleared"
      clearTime=str(ctime2)
    if iRec=="Cleared" and mExist=="True":
      break
  file8.close()
  if iRec=="Cleared" and mExist=="False":
    recExist="False"
    with open("/tmp/iamm.out", "ab+") as inFile:
      for line in inFile:
        if incID in line:
          recExist=="True"
          break
      if recExist=="False":
        inFile.write(incID+' , '+'Cleared'+' , '+clearTime+' , '+'iamM: '+mExist+'\n')
  return(mExist,iRec,clearTime)

def sInactive(incID):
  file=open("/tmp/issue.tmp","rb+")
  iRec="notCleared"
  for line in file:
    if incID in line and "INACTIVE" in line:
      iRec="Cleared"
      break
  file.close()
  return iRec

def reGroupEventId(eventId):
  issueDetail=""
  issueDetail1=""
  affCI=""
  eventId1=""
  eventId2=""
  issueGroup=""
  firstPart=""
  lastPart=""
  #print(eventId)
  if "NETIQ" in eventId and ":" in eventId:
    sp=[]
    sp=str(eventId).split(":")
    issueDetail=sp[1]
    firstPart=sp[0]
    if "2018" in issueDetail:
      sp3=[]
      sp3=str(issueDetail).split('2018')
      issueDetail=sp3[0]
    elif "2019" in issueDetail:
      sp3=[]
      sp3=str(issueDetail).split('2019')
      issueDetail=sp3[0]
    sp2=[]
    sp2=str(firstPart).split("_")
    affCI=sp2[3].strip() 
    eventId1="NETIQ_Trap-"+issueDetail
    eventId2="NETIQ_Trap-"+affCI+"-"+issueDetail
  elif "NETIQ" in eventId and ":" not in eventId:
    sp=[]
    sp=str(eventId).split("_")
    affCI=str(sp[3])
    sp2=[]
    sp2=str(eventId).split("_20[5137]_")
    issueDetail=sp2[1]
    eventId1="NETIQ_Trap-"+str(issueDetail)
    eventId2="NETIQ_Trap-"+str(affCI)+str(issueDetail)
  elif ("Host" in eventId or "Partition" in eventId or "FibreChannelSwitch" in eventId) and "Down" in eventId:
    sp=[]
    sp=str(eventId).split("_")
    affCI=sp[1]
    sp2=[]
    sp2=str(sp[0]).split("-")
    issueGroup=sp2[1] 
    eventId1=str(issueGroup)+"-Down"
    eventId2=str(issueGroup)+"-"+affCI+"-"+"Down"
  else: 
    sp=[]
    sp=str(eventId).split("-")
    issueGroup=sp[1]
    lastPart=sp[2]
    sp1=[]
    sp1=str(lastPart).split("/")
    affCI=sp1[0]
    sp2=[]
    sp2=str(eventId).split("_")
    issueDetail=sp2[-1].strip().strip('\n')
    if "2018" in issueDetail:
      sp3=[]
      sp3=str(issueDetail).split("2018")
      issueDetail=sp3[0]
    eventId1=str(issueGroup)+"-"+str(issueDetail)
    eventId2=str(issueGroup)+"-"+affCI+"-"+str(issueDetail)
  return(eventId1,eventId2)

##get token
##token will be effective for around 2 hours
##if task take more than 2 hours, need to get token again.
def renewToken():
  getToken='curl -k -s -o /tmp/token.out -X POST -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8"  -d  "grant_type=password&username=connectituser&password=ahkt3p5linaqi077461dpgm8sj&scope=individual,department,company&client_id=0IHITQdkF5FVB2ibb886EUN78wEa&client_secret=grbsQgfZbELFOmheOPoC6Tq9XeAa" '+' https://161.108.208.181:9443/oauth2/token'
  #print(getToken)

  os.system(getToken)

  with open("/tmp/token.out", "rb") as filet:
    tokenf=filet.readline()
  #print(tokenf)
  tokenf=json.loads(tokenf)
  token=tokenf["access_token"]
  return(token)

def getErrMsg2(token,iid,kiid):
  testCmd='curl -k -s -o /tmp/action2.out'+' -X GET -H "_TOKEN:'+token+'" -H "Content-Type: application/json" '+' \'https://ca-graph.hiroca.compucom.com/query/gremlin?query=outE.inV().has("ogit/Automation/knowledgeItemId",\"'+kiid+'\")&root='+iid+'\''
  os.system(testCmd)
  output_json = json.load(open('/tmp/action2.out'))
  etime="nodata"
  eTime="nodata"
  try:
    eTime=str(output_json['items'][0]['ogit/_created-on'])
    print(eTime)
    timestamp=int(eTime)/1000
    print(timestamp)
    value=datetime.datetime.fromtimestamp(timestamp)
    etime=value.strftime('%Y-%m-%d %H:%M:%S')
  except:
    return("Task failed","nodata","nodata")
  return("Get etime","nodata",etime)
 

def getErrMsg(token,iid,kiid):
  testCmd='curl -k -s -o /tmp/action.out'+' -X GET -H "_TOKEN:'+token+'" -H "Content-Type: application/json" '+' \'https://ca-graph.hiroca.compucom.com/query/gremlin?query=outE.inV().has("ogit/Automation/command","Action").has("ogit/Automation/knowledgeItemId",\"'+kiid+'\")&root='+iid+'\''
  #testCmd='curl -k -s -o /tmp/action.out'+' -X GET -H "_TOKEN:'+token+'" -H "Content-Type: application/json" '+' \'https://ca-graph.hiroca.compucom.com/query/gremlin?query=outE.inV().has("ogit/Automation/knowledgeItemId",\"'+kiid+'\")&root='+iid+'\''

  print("\n"+iid+' , '+kiid+"\n")
  print(testCmd)
  os.system(testCmd)

  output_json = json.load(open('/tmp/action.out'))
  etime="nodata"
  eTime="nodata"
  try:
    eTime=str(output_json['items'][0]['ogit/_created-on'])
    print(eTime)
    timestamp=int(eTime)/1000
    print(timestamp)
    value=datetime.datetime.fromtimestamp(timestamp)
    etime=value.strftime('%Y-%m-%d %H:%M:%S')
  except:
    return("Task failed","nodata","nodata")
  try:
    info=str(output_json['items'][0]['ogit/message'])
  except:
    return("Task failed","nodata","nodata")
  info=info.replace('\n','').replace(']','').replace('[','').replace('{','').replace('}','').replace('\"','').replace('\\','')
  info=info.replace(',','')
  info=re.sub(" +"," ",info)
  file=open("/tmp/kiActionRecord","a+")
  file.write(info+"\n\n")
  file.close()
  print("\n\n"+info+"\n\n")
  if "systemrc=0" in info or ("Local_Ping_Test" in info and "packets" in info):
    return("playbook executed successfully.",str(info),etime)
  if "msg:" in info:
    itm1=re.search(r'msg:(.*)',info)
    errMsg=itm1.group(1)
    itm2=re.search(r'ExtraVars=(.*)got:',info)
    execuInfo=itm2.group(1)
    info=str(execuInfo).strip()+" "+str(errMsg).strip()
    return("Task failed",str(info),etime)
  elif "output=" in info:
    return("Task failed",str(info),etime)
  return("Task failed",str(info),etime)

for f in glob.glob("/export/home/RIMusers/bgao/issue*"):
  os.remove(f)

for f in glob.glob("/export/home/RIMusers/issue*"):
  os.remove(f)

for g in glob.glob("/export/home/RIMusers/bgao/server*"):
  os.remove(g)

for g in glob.glob("/export/home/RIMusers/server*"):
  os.remove(g)

for g in glob.glob("/export/home/RIMusers/bgao/reports/server*"):
  os.remove(g)

for g in glob.glob("/export/home/RIMusers/bgao/reports/issue*"):
  os.remove(g)

for g in glob.glob("/export/home/RIMusers/bgao/reports/kiExe*"):
  os.remove(g)

#Erase the data in /tmp/incStatusTemp.out file
open("/tmp/incStatusTemp.out","w").close
open("/tmp/newTicket.tmp","w").close
open("/tmp/kiActionRecord","w").close

#getCurt="date +'%s'"
#status,times=commands.getstatusoutput(getCurt)
#timestamp=int(times)
#value=datetime.datetime.fromtimestamp(timestamp)
#curTT=value.strftime('%m%d')
fileN="issue"+curTT
fileN2="server"+curTT
#fileN="issue0721"
#fileN2="server0721"
#print(fileN)

token=renewToken()


def searchKiHistory(iid,eventID):
  file=open("/tmp/kiExecutionHistory.out", "r+")
  result=[]
  status="False"
  #if "SNMP" in eventID:
    #kiNumber=4
  #else:
    #kiNumber=3
  #kin=0
  
  for line in file:
    if iid in line:
      result.append(line)
      status="True"
      #kin += 1
    #elif kin >= kiNumber:
      #print("\n\n find all KIs associated to this ISSUE: "+str(result)+" .\n\n")
      #break
  file.close() 
  if status=="True":
    return("True",result)
  else:
    return("False","nodata")

def searchKiDetailedHistory(iid):
  file=open("/tmp/kiExecutionDetailedHistory.out","r+")
  result=""
  for line in file:
    if iid in line:
      result=line
      return(result)
  file.close()
  return("nodata")
    

def getOsType(affCI):
  ostype="nodata"
  sp1=[]
  sp1=str(affCI).split('.')
  basename=sp1[0].lower()
  file=open("/export/home/RIMusers/bgao/host.list2","rb+")
  for line in file:
    if basename in line:
      sp=[]
      sp=str(line).split(',')
      ostype=sp[3]
      if ostype=="nodata":
        ostype=sp[4]
  file.close()
  return(str(ostype))


autologin.main("nohup /usr/bin/python /export/home/RIMusers/bgao/extrInfoV2.py "+tmm+" "+tmm2+"  > /tmp/test0701.out2 2>&1 &")
time.sleep(200)
autologin.main("nohup /usr/bin/python /export/home/RIMusers/bgao/extrIssueInfo.py "+tmm+" "+tmm2+" > /tmp/test0701.out 2>&1 &") 
time.sleep(400)
i=0
while 1:
  if i > 20:
    print("\n Failed to download the file: "+fileN+"\n")
    sys.exit(2)
  try:
    downloadFile.dFile(fileN)
    fpath="/export/home/RIMusers/bgao/"+fileN
    if os.path.getsize(fpath):
      break
    else:
      time.sleep(30)
      i += 1
      continue
  except:
    time.sleep(30)
    print("\n Failed to download the file: "+fileN+" "+str(i)+" times.\n")
    i += 1
    continue
i=0
while 1:  
  if i > 20:
    print("\n Failed to download the file: "+fileN2+"\n")
    sys.exit(1)
  try:
    downloadFile.dFile(fileN2)
    fpath="/export/home/RIMusers/bgao/"+fileN2
    if os.path.getsize(fpath):
      break
    else:
      time.sleep(30)
      i += 1
      continue
  except:
    time.sleep(30)
    print("\n Failed to download the file: "+fileN2+" "+str(i)+" times. \n")
    i += 1
    continue
sortcommand="sort -k 2r "+fileN+" >issue.tmp"
sortcommand2="mv issue.tmp "+fileN
os.system(sortcommand)
#print(sortcommand)
os.system(sortcommand2)
#print(sortcommand2)

time.sleep(10)

shutil.copy2("/export/home/RIMusers/bgao/"+fileN,"/tmp/issue.tmp")
file1=open("/export/home/RIMusers/bgao/"+fileN,"rb")

sortcommandv2="sort -k 2 /tmp/issue.tmp >/tmp/issue.tmp2"
os.system(sortcommandv2)

workbook = xlsxwriter.Workbook("/export/home/RIMusers/bgao/"+fileN+'.xlsx')
worksheet = workbook.add_worksheet(fileN)
# Start from the first cell. Rows and columns are zero indexed.
bold = workbook.add_format({'bold': True})

worksheet.write(0,0, "iid",bold)
worksheet.write(0,1, "ctime",bold)
worksheet.write(0,2, "IssueTimeStamp",bold)
worksheet.write(0,3, "affectedCI",bold)
worksheet.write(0,4, "getTicketID",bold)
worksheet.write(0,5, "incID",bold)
worksheet.write(0,6, "eventStatus",bold)
worksheet.write(0,7, "sourceTicketID",bold)
worksheet.write(0,8, "state",bold)
worksheet.write(0,9, "Node",bold)
worksheet.write(0,10, "iamM",bold)
worksheet.write(0,11, "assignedGroup",bold)
worksheet.write(0,12, "masterID",bold)
worksheet.write(0,13, "SNOWstatus",bold)
worksheet.write(0,14, "notes",bold)
worksheet.write(0,15, "uTicket",bold)
worksheet.write(0,16, "cTicket",bold)
worksheet.write(0,17, "eventID",bold)
worksheet.write(0,18, "eventID1",bold)
worksheet.write(0,19, "eventID2",bold)
worksheet.write(0,20, "issueSubject",bold)
worksheet.write(0,21, "Cleared",bold)
worksheet.write(0,22, "ifConflict",bold)
worksheet.write(0,23, "event_description", bold)

worksheet.set_column('A:P',20)
worksheet.set_column('R:R',100)
worksheet.set_column('S:W',20)
worksheet.set_column('X:X',50)

row = 1
col = 0

iid=""
ctime=""
affectedCI=""
getTicketID=""
incID="nodata"
eventStatus=""
sourceTicketID=""
state=""
Node=""
iamM=""
assignedGroup=""
masterID=""
SNOWstatus=""
notes="nodata"
eventID=""
rOpenTicket=""
nResolvedTicket=""
nResolvedTicketN=0
uTicket=""
cTicket=""
rOpen=""
rTicket=""
iRec="notCleared"
orphanTicket=""
orphanTicketN=0
mExist=""
mExist2=""
sysErr=""
sysErr2=""
eMasterIssue=""
eMasterIssueN=0
eMasterIssueV2=""
eMasterIssueV2N=0
#hTicket=""
dupTicket=""
dupTicketN=0
fileReady="False"
ejectIssue=""
ejectIssueN=0
ejectIssueV2=""
ejectIssueV2N=0
noTicketIssueEjected=""
noTicketIssueEjectedN=0
iTimeStamp=""
troubleshootKIReport=""
note2=""
issueSubject=""
kis2=""
errMsg=""
kiSuceedN=0
kiTotal=0
kiExecutionResult=""
noActionDataN=0
briTicketN=0
incSum=""
eDescription=""


for line in file1:
  sp=[]
  sp=line.split(",")
  iid=sp[0].strip()
  ctime=sp[1].strip()
  affectedCI=sp[2].strip()
  getTicketID=sp[3].strip()
  incID=sp[4].strip()
  if not incID:
    incID="empty"
  eventStatus=sp[5].strip()
  sourceTicketID=sp[6].strip()
  state=sp[7].strip()
  Node=sp[8].strip()
  iamM=sp[9].strip()
  #assignedGroup=sp[10].strip()
  assignedGroup="nodata"
  #if not assignedGroup:
    #assignedGroup="empty"
  masterID=sp[11].strip()
  #SNOWstatus=sp[12].strip()
  SNOWstatus="nodata"
  uTicket=sp[13].strip()
  cTicket=sp[14].strip()
  eventID=sp[15].strip()
  if incID!="nodata" and incID!="empty":
    mExist="False"
    iRec="notCleared"
    clearTime="nodata"
    mExist,iRec,clearTime=sIAMM(incID)
    
  if eventID=="nodata":
    print(eventID)
    print(iid)
    #quit()
  if eventID!="nodata"and eventID:
    try:
      eventID1,eventID2=reGroupEventId(eventID)
    except:
      eventID1=eventID2="nodata"
      pass
  try:
    iTimeStamp=sp[16].strip()
  except:
    iTimeStamp="nodata"
  try:
    issueSubject=sp[17].strip()
  except:
    issueSubject="nodata"
  try:
    note2=sp[18].strip()
  except:
    note2="nodata"
  try:
    kis2=sp[19].strip().strip('\n')
  except:
    kis2="nodata"
  try:
    eDescription=sp[20].strip().strip('\n')
  except:
    eDescription="nodata"
  if eventID=="nodata":
    eventID=issueSubject
  #if incID!="nodata" and SNOWstatus!="Closed" and SNOWstatus!="Resolved" and "NETIQ" not in eventID:
  if incID!="nodata" and SNOWstatus!="Closed" and SNOWstatus!="Resolved" and incID!="empty":
    #try:
    SNOWstatus,assignedGroup=chkIncInfo(incID,iid)
    #time.sleep(1)
    print(incID+' , '+SNOWstatus+' , '+assignedGroup)
    #except:
      #pass
      #assignedGroup=sp[10].strip()
      #SNOWstatus=sp[12].strip()
  
   #if eventStatus=="INACTIVE" and state=="EJECTED" and uTicket=="True":
   # file8=open("/tmp/issue.tmp","rb")
   # rOpen=""
   # for line in file8:
   #   if affectedCI in line and eventID in line and "RESOLVED" in line and incID in line:
   #     rOpen='False'
   #     break      
   # file8.close()
   # if rOpen!='False':
   #   print("rOpen is: "+incID+' , '+rOpen)
   #   notes="ticket reopened"
   #   if incID not in rOpenTicket and incID!="nodata": 
   #     rOpenTicket = rOpenTicket + incID + '\n'
   #     #print("reopened ticket: " + incID)
  #if incID!="nodata" and incID!="empty" and SNOWstatus!="Resolved" and SNOWstatus!="Closed" and SNOWstatus!="nodata" and "NETIQ" not in line:
  if incID!="nodata" and incID!="empty" and SNOWstatus!="Resolved" and SNOWstatus!="Closed" and SNOWstatus!="nodata":
    #mExist="False"
    #iRec="notCleared"
    #try:
    #mExist,iRec,clearTime=sIAMM(incID)
    #except:
    #  pass
    if "True" not in mExist or "False" in mExist:
      notes="ticket resolved in Hiro,open in SNOW,iamM deleted,new alert will create new ticket,may duplicate." 
      if incID not in nResolvedTicket and incID!="nodata" and incID!="empty":
        nResolvedTicket = nResolvedTicket + incID + " , " + ctime + ' , '+SNOWstatus+' , '+ assignedGroup+' , '+affectedCI + ' , '+iRec+' , '+mExist+' , ' + str(eventID1) + "\n"
        nResolvedTicketN += 1
          #print("unresolved ticket: " + incID)
  if SNOWstatus!="Resolved" and SNOWstatus!="Closed" and SNOWstatus!="nodata" and incID!="nodata" and incID!="empty":
    #file=open("/tmp/issue.tmp","r+")
    #mExist="False"
    #iRec="notCleared"
    #ctime2=""
    #iRec="notCleared"
    #mExist,iRec=sIAMM(incID)
    #for line in file:
      #sp2=[]
      #sp2=line.split(',')
      #iamM3=sp2[9].strip()
      #ctime2=sp2[1].strip()
      #if incID in line and iamM3=="True":
      #  mExist="True"
      #  continue
      #if incID in line and "INACTIVE" in line:
      #  iRec="Cleared"
      #if mExist=="True" and iRec=="Cleared":
      #  break
    #file.close()
    if mExist=="True" and iRec=="Cleared":
      notes="CLEAR received,ticket open in Hiro and SNOW,Hiro error."
      if incID not in orphanTicket and incID!="nodata" and incID!="empty":
        orphanTicket = orphanTicket + incID + " , " + ctime + ' , ' + SNOWstatus+' , '+affectedCI + " , " + iRec + ' , '+mExist+' , '+str(eventID1) + "\n "     
        orphanTicketN += 1
  if (SNOWstatus=="Resolved" or SNOWstatus=="Closed") and iamM=="True" and incID!="nodata" and incID!="empty":
    #file=open("/tmp/issue.tmp",'rb+')
    #iiRec="notCleared"
    #for line in file:
    #  if incID in line and "INACTIVE" in line:
    #    iiRec="Cleared"
    #    break
    #file.close()
    if incID not in eMasterIssue:
      eMasterIssue = eMasterIssue +  iid + ' , ' + ctime + ' , ' + incID + ' , ' + SNOWstatus+' , '+affectedCI + ' , ' + iRec + ' , ' +iamM+' , '+ str(eventID1) + '\n'
      eMasterIssueN += 1
  if iamM=="True" and (incID=="nodata" or incID=="empty"):
    if incID not in eMasterIssueV2:
      eMasterIssueV2 = eMasterIssueV2 + iid + ' , ' + ctime + ' , ' + incID + ' , ' + SNOWstatus+' , '+affectedCI + ' , ' + state + ' , ' +str(eventID1) + '\n'
      eMasterIssueV2N += 1

  #if SNOWstatus=="nodata" and iamM=="True" and incID!="nodata":
    #if incID not in hTicket:
      #hTicket = hTicket + iid + ' , ' + incID + ' , ' + affectedCI + ' , ' + str(eventID1) + '\n'
  #filter all open data and put them in a new file.
  if fileReady=="False":  
    filen=open("/tmp/newTicket.tmp","a+")
    file=open("/tmp/issue.tmp","r+")
    for line in file:
      sp3=[]
      sp3=line.split(',')
      iid2=sp3[0].strip()
      ctime2=sp3[1].strip()
      affectedCI2=sp3[2].strip()
      incID2=sp3[4].strip()
      try:
        SNOWstatus2=sp3[9].strip()
      except:
        SNOWstatus2="No"
      if SNOWstatus2!="Closed" and SNOWstatus2!="Resolved" and incID2!="nodata" and incID2!="empty":
        try:
          SNOWstatus2,assignedGroup2=chkIncInfo(incID2,iid2)
          if SNOWstatus2!="Resolved" and SNOWstatus2!="Closed" and SNOWstatus2!="nodata":
            filen.write(line)
          #time.sleep(1)
            #print(line)
        except:
          pass
    fileReady="True"  
    file.close()
    filen.close()

  if SNOWstatus!="Resolved" and SNOWstatus!="Closed" and SNOWstatus!="nodata" and incID!="nodata" and incID!="empty":
    file=open("/tmp/newTicket.tmp","r+")
    dupStatus="False"
    for line in file:
      #print(line)
      sp3=[]
      sp3=line.split(',')
      iid2=sp3[0].strip()
      ctime2=sp3[1].strip()
      affectedCI2=sp3[2].strip()
      incID2=sp3[4].strip()      
      SNOWstatus2=sp3[9].strip()
      iTimeStamp2=sp3[16].strip().strip("\n")
      if affectedCI in line and eventID in line and SNOWstatus2!="Closed" and SNOWstatus2!="Resolved" and incID2!="nodata" and incID2!="empty":
        try:
          SNOWstatus2,assignedGroup2=chkIncInfo(incID2,iid2)
        except:
          pass
      
        if SNOWstatus2!="Resolved" and SNOWstatus2!="Closed" and SNOWstatus2!="nodata" and incID2!=incID:
          #assuming there may be more than 2 duplicated tickets in Service Now. 
          if incID2 not in dupTicket:
            mExist="False"
            iRec="notCleared"
            clearTime="nodata"
            mExist,iRec,clearTime=sIAMM(incID2)
            dupTicket = dupTicket + incID2 +':'+SNOWstatus2+':'+ctime2 + ':' + iRec + ':' +mExist + ' '
            dupStatus = "True"
    file.close() 
    if dupStatus == "True":
      #mExist="False"
      #iRec="notCleared"
      #mExist,iRec=sIAMM(incID)
      dupTicket = dupTicket + incID+':'+SNOWstatus+':'+ctime+':'+iRec+':'+mExist+','+affectedCI+','+eventID1+'\n'
      dupTicketN += 1
  if state=="EJECTED" and (SNOWstatus=="Resolved" or SNOWstatus=="Closed" or SNOWstatus=="nodata") and incID!="nodata" and incID!="empty":
    #mExist="False"
    #iRec="notCleared"
    #mExist,iRec=sIAMM(incID) 
    #iRec=sInactive(incID)
    if mExist=="False" and iRec=="Cleared":
      ejectIssue = ejectIssue + iid +' , '+ctime+' , '+incID+' , '+SNOWstatus+' , '+state+' , '+ iRec+' , '+mExist+' , '+affectedCI + ' , '+ eventID1+' , '+eventID2+'\n'
      ejectIssueN += 1
  if state=="EJECTED" and (incID=="nodata" or incID=="empty"):
    noTicketIssueEjected = noTicketIssueEjected + iid +' , '+ctime +' , '+affectedCI +' , '+state+' , '+incID+' , '+eventID1+' , '+eventID2+'\n'
    noTicketIssueEjectedN += 1

  #if str(issueSubject)[:4]=="BRI-" and "NETIQ" not in eventID:
  #if 'NETIQ' not in eventID and incID!="nodata" and SNOWstatus!="nodata" and incID!="empty":
  if str(issueSubject)[:4]=="BRI-" and incID!="nodata" and SNOWstatus!="nodata" and incID!="empty":
    if incID not in incSum:
      incSum = incSum + incID
      briTicketN += 1
    #if str(issueSubject)[:4]=="BRI-": 
      #briTicketN += 1
  if "BRI" in issueSubject and incID!="nodata" and SNOWstatus!="nodata" and incID!="empty":
    status="False"
    resultKiSearch=[]
    status,resultKiSearch=searchKiHistory(iid,eventID)
    print("\n\n search result: "+str(status)+' , '+str(resultKiSearch)+" \n\n")
    #process based on the restult of seaching Ki record
    flag="True"
    if status=="False":
      ostype="nodata"
      flag="False"
      try:
        ostype=getOsType(affectedCI)
      except:
        pass
      kis=""
      try:
        kis=getKiList(token,iid)
      except:
        token=renewToken()
        try:
          kis=getKiList(token,iid)
        except:
          continue
      kiid2=""
      kinamet=""
      kiSucced="Success"
      if "cjlx8opont5padd02k0eup42f" in kis[-1:]:
        kiSucced="Failed"
      #mExist="False"
      #iRec="notCleared"
      #mExist,iRec=sIAMM(incID)
      #index=0
      kiApplied="False"
      #kiSucced="True"
      print("\n\n KI list: "+str(kis)+"\n\n")
      for kiid2 in kis:
        kiSucced2="Failed"
        print(kiid2)
        file=open("/export/home/RIMusers/bgao/troubleshooting-KIv2.list","rb+") 
        kiname=""
        ansibleTask="no"
        for line in file:
          if kiid2 in line:
            kiApplied="True"
            errMsg1="nodata"
            #retreive the KI name
            sp8=[]
            sp8=str(line).split(",")
            kiname=sp8[0].strip()
            ansibleTask=sp8[2].strip().rstrip("\n")
            #check the name
            errMsg2="N/A"       
            succedNotes="N/A"
            status="NA"
            etime="nodata"
            errMsg888="nodata"
            #if "Initiate" in kiname or "Lower" in kiname or "Increase" in kiname or "Validate" in kiname or "Minutes" in kiname or "ITSM" in kiname or "SQL" in kiname or "Issue" in kiname or "Request" in kiname or "Chck" in kiname or "check" in kiname or "assign" in kiname or "reChk" in kiname or "Resolve" in kiname:
            if ansibleTask=="noAnsibleTask":
              print("\n"+kiid2+"\n")
              #errMsg2="no Ansible action for this KI."
              errMsg1="notApplicable"
              succedNotes="Kickoff: No playbook performed in this KI."
              status,errMsg888,etime=getErrMsg2(token,iid,kiid2)
              if etime=="nodata":
                etime=str(ctime)
            else:
              status,errMsg1,etime=getErrMsg(token,iid,kiid2)
              print("\n"+note2+"\n")
              if "JAVASCRIPT_EXCEPTION" in note2:
                status="Failed"
                errMsg1="JAVASCRIPT_EXCEPTION"
              #else:
                #flag="nodata"
                #flag=chkJavaScriptErr(incID,note2)
                #if "notFound" in flag:
                  #status="Failed"
                  #errMsg1="Failed to update Service Now."                

              if etime=="nodata":
                etime=str(ctime)
              print("\n\n status and errMsg: "+str(status)+' , '+str(errMsg1) +" \n\n ")
              if errMsg1=="nodata":
                noActionDataN += 1
                errMsg2="Failed to retreive action data from Hiro."
                print("\n\n"+errMsg2+"\n\n")
                print(iid+" , the kiid is: "+kiid2)
                with open("/tmp/action.out", "r") as fin:
                  print(fin.read())
                #sys.exit(0)
            if int(noActionDataN) > 5:
              print("\n\n There is no action data retreived 5 times from Hiro Database. there may be network issue, terminate script.\n\n")
              quit()

            if errMsg1!="notApplicable" and "playbook" not in status:
              kiSucced2="Failed"
            else: 
              kiSucced2="Succeeded"
            #succedNotes="nodata"
            if "playbook" in status:
              #kiSucced="True"
              succedNotes="nodata"
              files=open("/tmp/searchKeyWords.out","ab+")
              for line in files:
                sps=[]
                sps=str(line).split(',')
                keyword1=str(sps[0]).strip()
                keyword2=str(sps[1]).strip().rstrip('\n')
                print("\n\n"+keyword1+' , '+keyword2+"\n\n")
                try:
                  succedNotes=re.search(keyword1+"(.*)"+keyword2,errMsg1).group(1)
                  print(succedNotes)
                  if succedNotes != "nodata":
                    succedNotes=str(succedNotes).replace('msnn','ms').replace('msn','ms').replace('rn','')
                    succedNotes=succedNotes.replace(',',' . ').replace('end', ' ')
                    print("\n\n"+succedNotes+"\n\n")
                    #quit()
                    break
                except:
                  pass
              if succedNotes == "nodata":
                succedNotes=str(errMsg1) 
              files.close()
              #quit()
            elif "notApplicable" in errMsg1:
              print("not Applicable") 
            else:
              kiSucced="Failed"

            if errMsg1!="nodata" and errMsg1!="notApplicable":
              errMsg = str(errMsg) + " " + str(errMsg1)

            print("\n\n succed notes: "+succedNotes+"   \n\n")
          
            print("\n\n\n")
            print("Below is GREMLIN processing result:")
            print(errMsg)
            print("\n\n\n")
            ## write data into a string for analyzing.
            if "notApplicable" not in errMsg1 and "playbook" not in status and errMsg1!="nodata":
              if "100% packet loss" in errMsg1:
                errMsg2="server is not pingable."
              elif "Execution timed out" in errMsg1:
                errMsg2="timed out."
              elif "/wsman" in errMsg1 and "ConnectTimeoutError" in errMsg1:
                errMsg2="/wsman timeout in Ansible and server side" 
              elif "/wsman" in errMsg1 and "Errno 111 Connection refused" in errMsg1:
                errMsg2="Errno 111 Connection refused. server not configured properly."
              elif "Bad HTTP response" in errMsg1 and "Code 500" in errMsg1:
                errMsg2="Code 500. server is run out of resources."
              elif "FATAL ERROR DURING FILE TRANSFER" in errMsg1:
                errMsg2="transfer failure. check server and ansible configuration." 
              elif "remote handler timeout" in errMsg1:
                errMsg2="remote handler timeout."
              elif "MODULE FAILURE" in errMsg1:
                errMsg2="MODULE FAILURE."
              elif "ssh" in errMsg1 and "Connection timed out during banner exchange" in errMsg1:
                errMsg2="ssh timeout between Ansible and server. may need increase timeout on Ansible side."
              elif "ssh" in errMsg1 and "Permission denied" in errMsg1:
                errMsg2="ssh not configured properly."
              elif "ssh" in errMsg1 and "Connection timed out" in errMsg1:
                errMsg2="ssh connection timed out. may caused by network issue."
              elif "timeout=30" in errMsg1 and "HTTPSConnectionPool" in errMsg1:
                errMsg2="HTTPSConnectionPool port=5986 read timeout=30 on Ansible side."
              elif "winrm send_input failed" in errMsg1:
                errMsg2="winrm send_input failed. server is not ansible ready."
              elif "bad handshake" in errMsg1 and "ssl" in errMsg1:
                errMsg2="ssl bad handshake. server is not ansible ready."
              elif "FileOpenFailure" in errMsg1:
                errMsg2="FileOpenFailure in server side."
              elif "ssl requires a password" in errMsg1:
                errMsg2="ssl requires a password"
              elif "ailure during module execution" in errMsg1:
                errMsg2="Failure during module execution"
              else:
                errMsg2=errMsg1


            kiExecutionResult = kiExecutionResult + kiname+','+incID+','+ iid + ',' +ctime+','+etime+','+ kiSucced2 + ','+ affectedCI + ',' + ostype+','+SNOWstatus+','+assignedGroup+','+iRec+','+clearTime+','+mExist+','+errMsg2+','+eventID1+','+succedNotes+','+note2+',' +kiSucced+','+str(flag)+'\n'
            #if clearTime!="nodata":
              #with open("/tmp/kiExecutionHistory.out", "a+") as khFile:
                #khFile.write(kiname+' , '+incID+' , '+ iid + ' , ' +ctime+' , '+etime+' , '+ kiSucced2 + ' , '+ affectedCI + ' , ' + ostype+' , '+SNOWstatus+' , '+assignedGroup+' , '+iRec+' , '+clearTime+' , '+mExist+' , '+errMsg2+' , '+eventID1+' , '+succedNotes+' , '+note2+' , '+kiSucced+' \n ')
 
            if kiname not in kinamet:
              kinamet += kiname+':'
            break
        file.close()
      
        #index += 1
      #if kiApplied=="True":
        #kiTotal += 1
      #if kiSucced=="True" and kiApplied=="True":
        #kiSuceedN += 1 
      if not kinamet:
        kinamet="nodata"
      
      troubleshootKIReport = troubleshootKIReport + iid + ','+ctime+','+affectedCI+','+ostype+','+incID+','+kinamet+','+SNOWstatus+','+state+','+mExist+','+iRec+','+eventID1+','+note2+','+errMsg+','+kiSucced+'\n'    
      if kinamet!="nodata":
        with open("/tmp/kiExecutionDetailedHistory.out", "a+") as hddFile:
          hddFile.write(iid + ','+ctime+','+affectedCI+','+ostype+','+incID+','+kinamet+','+SNOWstatus+','+state+','+mExist+','+iRec+','+eventID1+','+note2+','+errMsg+','+kiSucced+'\n')

    #find record in Ki history record
    else: 
      result1=""
      result1=searchKiDetailedHistory(iid)
      #kiTotal += 1
      #if "Succeed" in result1:
        #kiSuceedN += 1
      if result1=="nodata":
        print("failed to find: "+iid+" in Ki detailed history record!!\n")
        quit()
      else:
        troubleshootKIReport = troubleshootKIReport + result1
      k=0
      kiSuceed="Success"
      while k < len(resultKiSearch):
        kiExecutionResult=kiExecutionResult + resultKiSearch[k]
        if "Fail" in resultKiSearch[k]:
          kiSuceed="Failed"
        k += 1  
      #if kiSuceed=="True":
        #kiSuceedN += 1
  bCI=[]
  bCI=str(affectedCI).split('.')
  baseCI=""
  baseCIUpper=""
  baseCI=bCI[0]
  baseCIUpper=baseCI.upper()
  print(baseCI)
  print(eventID)
  ifConflict="False"
  if ".isv" in eventID or ".ISV" in eventID:
    if baseCI not in eventID and baseCIUpper not in eventID:
      ifConflict="True"
  print(ifConflict)
  #quit()
  #if "INC" in incID and "Closed" not in SNOWstatus and "Resolved" not in SNOWstatus and "HIRO" in assignedGroup:
    #chkTime="noIssue"
    #chkTime=getUnixTime(ctime)
    #if "issueFound" in chkTime:
      #hiroFile.write(iid+" , "+incID+" , "+affectedCI+" , "+ctime+" , "+assignedGroup+" , "+SNOWstatus+" , "+eventID1+"\n")
      #print("issue found with Hiro queue.")
    #else:
      #print("no issue found!")

  worksheet.write(row, col, iid)
  worksheet.write(row, col+1, ctime)
  worksheet.write(row, col+2, iTimeStamp)
  worksheet.write(row, col+3, affectedCI)
  worksheet.write(row, col+4, getTicketID)
  worksheet.write(row, col+5, incID)
  worksheet.write(row, col+6, eventStatus)
  worksheet.write(row, col+7, sourceTicketID)
  worksheet.write(row, col+8, state)
  worksheet.write(row, col+9, Node)
  worksheet.write(row, col+10, iamM)
  worksheet.write(row, col+11, assignedGroup)
  worksheet.write(row, col+12, masterID)
  worksheet.write(row, col+13, SNOWstatus)
  worksheet.write(row, col+14, notes)
  worksheet.write(row, col+15, uTicket)
  worksheet.write(row, col+16, cTicket)
  worksheet.write(row, col+17, eventID) 
  worksheet.write(row, col+18, eventID1)
  worksheet.write(row, col+19, eventID2)
  worksheet.write(row, col+20, issueSubject)
  worksheet.write(row, col+21, iRec)
  worksheet.write(row, col+22, ifConflict)
  worksheet.write(row, col+23, eDescription)
 
  row +=1
  iid=""
  ctime=""
  affectedCI=""
  getTicketID=""
  incID="nodata"
  eventStatus=""
  sourceTicketID=""
  state=""
  Node=""
  iamM=""
  assignedGroup=""
  masterID=""
  SNOWstatus=""
  notes="nodata"
  eventID=""
  eventID1=""
  eventID2=""
  iTimeStamp=""
  uTicket=""
  cTicket=""
  rOpen=""
  rTicket=""
  iRec="False"
  mExist="False"
  issueSubject=""
  kis2=""
  note2=""
  kinamet=""
  errMsg=""
  eDescription=""

worksheet.autofilter('A1:X1200')
workbook.close()
file1.close()
#hiroFile.close()

noTicketIssueEjectedV2=""
dupTicketV2=""
orphanTicketV2=""
eMasterIssueV3=""
ejectIssueV2=""
eMasterIssueV4=""
nResolvedTicketV2=""


with open("/tmp/kiExeResult.txt","w") as kiResult:
  kiResult.write(kiExecutionResult)

shutil.copy2("/tmp/kiExeResult.txt","/tmp/kiExeResult2.txt")

def getKiExeResult(incID):
  kiSucced="Success"
  kiCount=1
  with open("/tmp/kiExeResult2.txt","r") as input:
    for line in input:
      if incID in line:
        if "Kickoff" not in line:
          kiCount += 1
        sp=[]
        sp=line.split(',')
        kiResult=sp[17]
        kiname=sp[0]
        #if "SQL" in kiname and "4 times" not in kiname:
          #kiSucced="Failed"
        #if "SQL" in kiname and "4 times" in kiname:
          #return("Success")
        #if "reChck" in kiname:
          #kiSucced="Failed"
        #if  "Chck" in kiname and "re" not in kiname:
          #return("Success")
        if "Failed" in kiResult:
          kiSucced="Failed"
          return("Failed")
    if kiCount == 1:
      kiSucced="Failed"
    return(kiSucced) 
        
         
       
kiTotal=0
kiSuceedN=0
incExeResult=""
kiExecutionResultt=""
with open("/tmp/kiExeResult.txt","r") as kiFile:
  for line in kiFile:
    if line.strip()!="":
      sp=[]
      sp=line.split(',')
      kiname=sp[0].strip()
      incID=sp[1].strip()
      iid=sp[2].strip()
      ctime=sp[3].strip()
      etime=sp[4].strip()
      kiSucced2=sp[5].strip()
      affectedCI=sp[6].strip()
      ostype=sp[7].strip()
      SNOWstatus=sp[8].strip()
      assignedGroup=sp[9].strip()
      iRec=sp[10].strip()
      clearTime=sp[11].strip()
      mExist=sp[12].strip()
      errMsg2=sp[13]
      eventID1=sp[14].strip()
      succedNotes=sp[15]
      note2=sp[16]
      kiSucced=sp[17].strip()
      flag=sp[18].strip()
      if "False" in flag:
        kiSucced=getKiExeResult(incID) 

      kiExecutionResultt = kiExecutionResultt + kiname+','+incID+','+ iid + ',' +ctime+','+etime+','+ kiSucced2 + ','+ affectedCI + ',' + ostype+','+SNOWstatus+','+assignedGroup+','+iRec+','+clearTime+','+mExist+','+errMsg2+','+eventID1+','+succedNotes+','+note2+','+kiSucced+'\n'
      if "False" in flag  and clearTime!="nodata" and mExist=="False" and ("Closed" in SNOWstatus or "Resolved" in SNOWstatus):
        with open("/tmp/kiExecutionHistory.out", "a+") as khFile:
          flag="True"
          khFile.write(kiname+','+incID+','+ iid + ',' +ctime+','+etime+','+ kiSucced2 + ','+ affectedCI + ',' + ostype+','+SNOWstatus+','+assignedGroup+','+iRec+','+clearTime+','+mExist+','+errMsg2+','+eventID1+','+succedNotes+','+note2+','+kiSucced+','+str(flag)+'\n')

      if incID not in incExeResult:
        incExeResult = incExeResult + incID + ' , '+kiSucced+ '\n'
        kiTotal += 1
        if "Success" in kiSucced:
          kiSuceedN += 1
       
with open("/tmp/incSum.out","w+") as outFile:
  outFile.write(incExeResult)

noTicketIssueEjectedV2=noTicketIssueEjected.replace("\n",",")
dupTicketV2=dupTicket.replace("\n",",")
try:
  crExcel.main(str(noTicketIssueEjectedV2),"noTicketIssueEjected","iid","ctime","affectedCI","state","ticket","eventID","eventID2")
except:
  pass
try:
  crExcel.main(str(dupTicketV2),"dupTicket","ticket:SNOWstatus:ctime:Cleared:IAMMExist","affectedCI","eventID")
except:
  pass
nResolvedTicketV2=nResolvedTicket.replace("\n",",")
try:
  crExcel.main(str(nResolvedTicketV2),"snowOpenIAMMdeleted","ticket","ctime","SNOWstatus","assignedGroup","affectedCI","Cleared","IAMMasterExist","eventID")
except:
  pass
try:
  orphanTicketV2=orphanTicket.replace("\n",",")
  crExcel.main(str(orphanTicketV2),"clearedButOpenInBoth","ticket","ctime","SNOWstatus","affectedCI","Cleared","IAMMasterExist","eventID")
except:
  pass
try:
  eMasterIssueV3=eMasterIssueV2.replace("\n",",")
  crExcel.main(str(eMasterIssueV3),"noTicketIAMMexist","iid","ctime","ticket","SNOWstatus","affectedCI","state","eventID")
except:
  pass
try:
  ejectIssueV2=ejectIssue.replace("\n",",")
  crExcel.main(str(ejectIssueV2),"ejectedResolvedInBoth","iid","ctime","ticket","SNOWstatus","state","ClearReceived","IAMMasterExist","affectedCI","eventID","eventID2")
except:
  pass
try:
  eMasterIssueV4=eMasterIssue.replace("\n",",")
  crExcel.main(str(eMasterIssueV4),"snowCloseIAMMexist","iid","ctime","ticket","SNOWstatus","affectedCI","ClearReceived","IAMMasterExist","eventID")
except:
  pass
troubleshootKIReport2=troubleshootKIReport.replace("\n",",")
crExcel.main(str(troubleshootKIReport2),"troubleshootingKIReport","iid","ctime","affectedCI","ostype","ticket","KI-Name","SNOWstatus","state","IAMMasterExist","Cleared","eventID","notes","errMsg","KiExecutionResult")
kiExecutionResultt=kiExecutionResultt.replace("\n",",")
crExcel.main(str(kiExecutionResultt),"kiExecutionReport"+str(curTT),"KI-Name","incId","iid","ctime","etime","result","affectedCI","osType","SNOWstatus","assignedGroup","ClearReceived","clearTime","IAMMasterExist","errMsg","eventId","ExtraInfomation","SNOW-Notes","KIExeResultForTicket")

os.rename("/export/home/RIMusers/bgao/"+fileN+".xlsx", "/export/home/RIMusers/bgao/reports/"+fileN+".xlsx")
#analyze ejected Issue
try:
  analyzeExcel.main("ejectedResolvedInBoth.xlsx","eventID2","eventID")
except:
  pass
try:
  analyzeExcel.main("noTicketIssueEjected.xlsx","eventID2","eventID")
except:
  pass
try:
  analyzeExcel.main(fileN+".xlsx","eventID2","eventID1","affectedCI","state","SNOWstatus","incID","assignedGroup")
  analyzeExcel.main("troubleshootingKIReport.xlsx","KI-Name")
except:
  pass
analyzeExcel.analyzeTable("kiExecutionReport"+str(curTT)+".xlsx","incId","KI-Name,result")
try:
  formatExcel.main("ejectedResolvedInBoth.xlsx")
except:
  pass
try:
  formatExcel.main("noTicketIssueEjected.xlsx")
except:
  pass
formatExcel.main(fileN+".xlsx")
try:
  formatExcel.main("snowOpenIAMMdeleted.xlsx")
except:
  pass
try:
  formatExcel.main("clearedButOpenInBoth.xlsx")
except:
  pass
try:
  formatExcel.main("snowCloseIAMMexist.xlsx")
except:
  pass
formatExcel.main("kiExecutionReport"+str(curTT)+".xlsx")
 
fileE=open("/tmp/issue.txt", "w+")
fileE.write("Hi Team:\n\n")
fileE.write("the following reports are generated from "+sTime+" to "+eTime+" .\n\n")
fileE.write("IAMMaster exists, No ticket created in SNOW(not Monitored?): "+str(eMasterIssueV2N)+"\n\n")
#fileE.write(eMasterIssueV2+"\n\n")
fileE.write("CLEAR received,ticket open in Hiro and SNOW,IAMMaster exists(JavaScript Error?): "+str(orphanTicketN)+"\n\n")
#fileE.write(orphanTicket+"\n\n")
fileE.write("Duplicated tickets in Service Now: "+str(dupTicketN)+"\n\n")
#fileE.write(dupTicket+"\n")
fileE.write("Ticket resolved in Hiro,open in SNOW,iamM deleted,new alert will create new ticket.")
fileE.write("This may create duplicate tickets. NetIQ_trap excluded: "+str(nResolvedTicketN)+"\n\n")
#fileE.write(nResolvedTicket+"\n\n")
fileE.write("Issue ejected,ticket resolved in SNOW,CLEAR received,IAMMaster deleted(needs to be cleanup up): "+str(ejectIssueN)+"\n\n")
#fileE.write(ejectIssue+"\n")
fileE.write("Issue ejected,no ticket associated(needed to be cleaned up): "+str(noTicketIssueEjectedN)+"\n\n")
#fileE.write(noTicketIssueEjected+'\n')
fileE.write("Tickets resolved in Service Now,IAMMaster exists in Hiro(new alert may be associated to closed ticket and get ignored by operation team,need to delete IAMMaster in HIRO): "+str(eMasterIssueN)+"\n\n")
#fileE.write("Troubleshooting KI applied to: " + str(kiTotal) + " tickets in total. and "+ str(kiSuceedN) + "  executed as expected!\n")
#fileE.write("Executed as expected means there is no configuration and communication issue spotted among Hiro, Mule, Ansible and related server.\n\n")
#fileE.write(eMasterIssue+"\n\n") 
#fileE.write("Check if there are tickets hold in hiro queue for more than 4 hours:\n")
#with open("/tmp/hiroQueue.out","r") as hirofile:
  #for line in hirofile:
    #fileE.write(line)
fileE.write("\n\n")
fileE.write("Regards,\n")
fileE.close()

subj1="Issue report"
fileE1="/tmp/issue.txt"
#att1="/export/home/RIMusers/bgao/"+fileN+'.xlsx'
att1=["/export/home/RIMusers/bgao/reports/dupTicket.xlsx","/export/home/RIMusers/bgao/reports/snowOpenIAMMdeleted.xlsx","/export/home/RIMusers/bgao/reports/clearedButOpenInBoth.xlsx","/export/home/RIMusers/bgao/reports/snowCloseIAMMexist.xlsx","/export/home/RIMusers/bgao/reports/noTicketIAMMexist.xlsx","/export/home/RIMusers/bgao/reports/noTicketIssueEjected.xlsx","/export/home/RIMusers/bgao/reports/ejectedResolvedInBoth.xlsx","/export/home/RIMusers/bgao/reports/troubleshootingKIReport.xlsx","/export/home/RIMusers/bgao/reports/"+fileN+".xlsx"]

#fileE=open("/tmp/marsnode.txt", "w+")
#fileE.write("Hi Gents:\n\n")
#fileE.write("  Attached is the Mars Node report, please review.\n")
#fileE.write("Regards,\n")
#fileE.close()

file2=open("/export/home/RIMusers/bgao/"+fileN2,"rb")
shutil.copy2("/export/home/RIMusers/bgao/"+fileN2,"/tmp/marsnode.tmp")
shutil.copy2("/export/home/RIMusers/bgao/"+fileN2,"/export/home/RIMusers/bgao/host.list2")
workbook2 = xlsxwriter.Workbook("/export/home/RIMusers/bgao/"+fileN2+'.xlsx')
worksheet2 = workbook2.add_worksheet(fileN2)
# Start from the first cell. Rows and columns are zero indexed.
bold2 = workbook2.add_format({'bold': True})

worksheet2.write(0,0, "IID",bold2)
worksheet2.write(0,1, "Basename",bold2)
worksheet2.write(0,2, "IPAddress",bold2)
worksheet2.write(0,3, "osName",bold2)
worksheet2.write(0,4, "MachineClass",bold2)
worksheet2.write(0,5, "Monitored",bold2)
worksheet2.write(0,6, "supportGroup",bold2)
worksheet2.write(0,7, "ogithost",bold2)
worksheet2.write(0,8, "ogitfirewall",bold2)
worksheet2.write(0,9, "fqdn",bold2)
worksheet2.write(0,10,"ogitfqdq",bold2)
worksheet2.write(0,11, "conflict",bold2)

worksheet2.set_column('A:J',20)

row2 = 1
col2 = 0

iid=""
Basename=""
IPAddress=""
osName=""
MachineClass=""
Monitored=""
supportGroup=""
ogithost=""
ogitfirewall=""
conflict="No"
noIpInHiro=""
noIpInSnow=""
nameErr=""
noSgInHiro=""
noSgInSnow=""
dupNodes=""
missingMonAttr=""
virtualSystemType=""
noVirtualSystemType=""
nofqdn=""
noogitfqdn=""

for line in file2:
  sp=[]
  sp=line.split(",")
  iid=sp[0].strip()
  if "compucom.com" in iid:
    continue
  Basename=sp[1].strip()
  if Basename not in iid and "connectit" not in line:
    conflict="Yes"
    nameErr=nameErr+"      "+iid
  IPAddress=sp[2].strip().rstrip("\n")
  osName=sp[3].strip()
  MachineClass=sp[4].strip()
  Monitored=sp[5].strip()
  supportGroup=sp[6].strip()
  ogithost=sp[7].strip()
  ogitfirewall=sp[8].strip().rstrip("\n")
  try:
    virtualSystemType=sp[9].strip().rstrip("\n")
  except:
    virtualSystemType="nodata"
  fqdn=sp[10].strip()
  ogitfqdn=sp[11].strip().rstrip("\n")
  if "Appliance" in MachineClass or "Switch" in MachineClass or "nodata" in MachineClass:
    continue
  if IPAddress=="nodata" and "Frame" not in osName and ogithost!="nodata" and osName!="nodata":
    if searchNode("/tmp/marsnode.tmp",Basename,"IPAddress")==0:
      noIpInHiro=noIpInHiro+"      "+iid+"\n"
  if IPAddress=="nodata" and "Frame" not in osName and ogithost=="nodata" and osName!="nodata":
    if searchNode("/tmp/marsnode.tmp",Basename,"ogithost")==0:
      noIpInSnow=noIpInSnow+"      "+iid+"\n"
  if supportGroup=="nodata" and ogitfirewall!="nodata" and osName!="nodata":
    if searchNode("/tmp/marsnode.tmp",Basename,"supportGroup")==0:
      noSgInHiro=noSgInHiro+"      "+iid+"\n"
  if supportGroup=="nodata" and ogitfirewall=="nodata" and osName!="nodata":
    if searchNode("/tmp/marsnode.tmp",Basename,"ogitfirewall")==0:
      noSgInSnow=noSgInSnow+"      "+iid+"\n"
  if chkDupNode("/tmp/marsnode.tmp",Basename)>1:
    if Basename not in dupNodes:
      dupNodes=dupNodes+"      "+Basename+"\n"
  if "missingAttr" in Monitored and "Default" not in iid:
    missingMonAttr=missingMonAttr+"    "+iid+"\n"
  if "nodata" in virtualSystemType:
    noVirtualSystemType=noVirtualSystemType+"   "+iid+"\n"
  if "nodata" in fqdn:
    nofqdn=nofqdn+"  "+iid+"\n"
  if "nodata" in ogitfqdn:
    noogitfqdn=noogitfqdn+"  "+iid+"\n"
      

  worksheet2.write(row2,col2, iid)
  worksheet2.write(row2,col2+1,Basename)
  worksheet2.write(row2,col2+2,IPAddress)
  worksheet2.write(row2,col2+3,osName)
  worksheet2.write(row2,col2+4,MachineClass)
  worksheet2.write(row2,col2+5,Monitored)
  worksheet2.write(row2,col2+6,supportGroup)
  worksheet2.write(row2,col2+7,ogithost)
  worksheet2.write(row2,col2+8,ogitfirewall)
  worksheet2.write(row2,col2+9,fqdn)
  worksheet2.write(row2,col2+10,ogitfqdn)
  worksheet2.write(row2,col2+11,conflict)

  row2 +=1
  iid=""
  Basename=""
  IPAddress=""
  osName=""
  MachineClass=""
  Monitored=""
  supportGroup=""
  ogithost=""
  ogitfirewall=""
  conflict="No"
  fqdn=""
  ogitfqdn=""
  
worksheet2.autofilter('A1:J1000')
workbook2.close()
file2.close()


fileE=open("/tmp/marsnode.txt", "w+")
fileE.write("Hi Gents:\n\n")
fileE.write("  Below is the serever list whose basename is not correct:\n")
fileE.write(nameErr+"\n")
fileE.write("  Below is the server list which has no IPAddress in Hiro:\n")
fileE.write(noIpInHiro+"\n")
fileE.write("  Below is the server list which has no ip address in SNOW:\n")
fileE.write(noIpInSnow+"\n")
fileE.write("  Below is the server list which has no support group in Hiro:\n")
fileE.write(noSgInHiro+"\n")
fileE.write("  Below is the server list which has no support group in SNOW:\n")
fileE.write(noSgInSnow+"\n")
fileE.write("  Below is the server list which has no Montored attribute in HIRO:\n")
fileE.write(missingMonAttr+"\n")
fileE.write("  Below is the server list which has no virtualSystemType in HIRO:\n")
fileE.write(noVirtualSystemType+"\n")
fileE.write("  Below is the server list which have duplicated nodes in Hiro:\n")
fileE.write(dupNodes+"\n")
fileE.write("  Below is the server list which have no fqdn in Hiro:\n")
fileE.write(nofqdn+"\n") 
fileE.write("  Below is the server list which have no fqdn in SNOW:\n")
fileE.write(noogitfqdn+"\n\n\n")
fileE.write("Regards,\n")
fileE.close()


subj2="Mars node report"
fileE2="/tmp/marsnode.txt"
os.rename("/export/home/RIMusers/bgao/"+fileN2+".xlsx", "/export/home/RIMusers/bgao/reports/"+fileN2+".xlsx")
#os.rename("/export/home/RIMusers/bgao/"+fileN+".xlsx", "/export/home/RIMusers/bgao/reports/"+fileN+".xlsx")
fileName2=fileN2+".xlsx"
#split() to convert string to list
att2=["/export/home/RIMusers/bgao/reports/"+str(fileName2)]

subj3="Troubleshooting KI execution daily report"
fileF=open("/tmp/kireport.txt","w+")
fileF.write("Hi team:\n\n")
fileF.write("Total tickt number(NETIQ ticket included): "+str(briTicketN)+". Troubleshooting KI applied to: " + str(kiTotal) + " tickets in total. and "+ str(kiSuceedN) + "  executed as expected, from "+sTime+" to "+eTime+" CST.\n")
#fileF.write("Executed as expected means there is no configuration and communication issue spotted among Hiro, Mule, Ansible and related server.\n")
fileF.write("attached is the details, plese review. \n\n")
fileF.write("Regards. \n")
fileF.close()

fileE3="/tmp/kireport.txt"
att4=["/export/home/RIMusers/bgao/reports/kiExecutionReport"+str(curTT)+".xlsx","/export/home/RIMusers/bgao/reports/troubleshootingKIReport.xlsx"]
att3=["/export/home/RIMusers/bgao/reports/kiExecutionReport"+str(curTT)+".xlsx"]


sendEmail.sendEmail(subj1,fileE1, att1,"bill.gao@compucom.com")
sendEmail.sendEmail(subj2,fileE2, att2,"bill.gao@compucom.com")
if "24" in tmm:
  sendEmailV2.sendEmail(subj3,fileE3, att3,"gqrlt1207@gmail.com","bill.gao@compucom.com")
elif "360" in tmm:
  #sendEmailV2.sendEmail(subj3,fileE3, att3,"bill.gao@compucom.com")
  sendEmail.sendEmail(subj3,fileE3, att3,"bill.gao@compucom.com")
else:
  #sendEmailV2.sendEmail(subj3,fileE3, att4,"bill.gao@compucom.com")
  sendEmail.sendEmail(subj3,fileE3, att3,"bill.gao@compucom.com")
