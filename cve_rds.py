import boto3
import numpy as np
import requests

from jira import JIRA
from ares import CVESearch
from prettytable import PrettyTable
import textwrap
from slackclient import SlackClient

table = PrettyTable(header_style='upper',field_names=["Database Name", "Engine Name", "Engine version", "Region",'Availability Zone',"CVE ID","Score","Impact"])
impactTable = PrettyTable(header_style='upper',field_names=["Database Name", "Engine Name", "Engine version", "Region",'Availability Zone',"CVE ID","Score","Impact"])
securityAdminsession = boto3.Session(profile_name='securityAdmin' , region_name='us-west-2')
cve = CVESearch()
ec2 = securityAdminsession.client('ec2')
regions = ec2.describe_regions()
for region in regions["Regions"]:
   source = securityAdminsession.client('rds',region_name=region["RegionName"])
   instances = source.describe_db_instances()
   db_instanceCount=np.array(instances.get('DBInstances')).size
   for dbInstance in instances.get('DBInstances'):
      engine_version = dbInstance.get('EngineVersion')
      engine = dbInstance.get('Engine')
      dbName = dbInstance.get('MasterUsername')
      availability_Zone=dbInstance.get('AvailabilityZone')

      if( engine == "mysql" ):
         dbvendor=cve.search('oracle/mysql')
         key="cpe:2.3:a:oracle:mysql:"+engine_version
      if( engine == "postgres" ):
         dbvendor=cve.search('postgresql/postgresql')
         key="cpe:2.3:a:postgresql:postgresql:"+engine_version

      print("CVE for: "+key)
      output_dict = [x for x in dbvendor if x['vulnerable_configuration'].count(key)>0]
      print("Account ID: ",dbInstance.get('DBInstanceArn').split(':')[4])
      print("Database Name: ",dbName)
      print("Engine Name: ",engine)
      print("Engine version: ",engine_version )
      print("Region: ",region["RegionName"])
      print("Availability Zone: ",availability_Zone)
      print("CVE ID: "+output_dict[0]["id"])
      print("Score "+str(output_dict[0]["cvss"]))
      print("Summary:"+output_dict[0]["summary"])
      print("=====================")
      
      databaseName=str(dbName)
      engineName=str(engine)
      engineVersion=str(engine_version)
      regionName=str(region["RegionName"])
      availabilityZone=str(availability_Zone)
      CVEID=str(output_dict[0]["id"])
      CVSS=str(output_dict[0]["cvss"])
      summary=str(output_dict[0]["summary"])
      
      if(float(output_dict[0]["cvss"]) >= 6.6):
         impact="high"
      elif(float(output_dict[0]["cvss"]) >= 4.1 and float(output_dict[0]["cvss"]) <= 6.5):
         impact="medium"
      else:
         impact="low"

      table.add_row([databaseName,engineName,engineVersion,regionName,availabilityZone,CVEID,CVSS,impact])

      if( impact == "low" ): 
         impactTable.add_row([databaseName,engineName,engineVersion,regionName,availabilityZone,CVEID,CVSS,impact])

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
jira = JIRA({'server':'https://sunnysimhadri07.atlassian.net','verify':False}, basic_auth=('sunny.simhadri@gmail.com', 'q6EcEncBLjKGmlWmwSII39CB'))
new_issue = jira.create_issue(project='10000', summary='New issue from jira-python',description=table.get_string(), issuetype={'name': 'Story'}) 



print(table)
if(impactTable.rowcount > 0):
   slack_token = "xoxb-447000172100-447001621796-1LmPxW4EvICx4gMuRJo254hv"
   sc = SlackClient(slack_token)
   sc.api_call(
        "chat.postMessage",
        channel="#general",
        #text='https://sunnysimhadri07.atlassian.net/browse/'+str(new_issue) ,
        
        text=table.get_string() ,
        type= "message",
   )
