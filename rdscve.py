
import boto3
import numpy as np
from ares import CVESearch
from prettytable import PrettyTable
import textwrap
from slackclient import SlackClient

table = PrettyTable(header_style='upper',field_names=["Database Name", "Engine Name", "Engine version", "Region",'Availability Zone',"CVE ID","Score","Impact","Summary"])
impactTable = PrettyTable(header_style='upper',field_names=["Database Name", "Engine Name", "Engine version", "Region",'Availability Zone',"CVE ID","Score","Impact","Summary"])
cve = CVESearch()
ec2 = boto3.client('ec2')
regions = ec2.describe_regions()
for region in regions["Regions"]:
   source = boto3.client('rds',region_name=region["RegionName"])
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

      if(float(output_dict[0]["cvss"]) >= 7.0):
         impact="high"
      elif(float(output_dict[0]["cvss"]) >= 4.1 and float(output_dict[0]["cvss"]) <= 6.0):
         impact="medium"
      else:
         impact="low"

      table.add_row([databaseName,engineName,engineVersion,regionName,availabilityZone,CVEID,CVSS,impact,textwrap.fill(summary,30)])

      if( impact == "low" ): 
         impactTable.add_row([databaseName,engineName,engineVersion,regionName,availabilityZone,CVEID,CVSS,impact,textwrap.fill(summary,30)])
         
print(table)
if(impactTable.rowcount > 0):
   slack_token = "xoxb-447000172100-447001621796-1LmPxW4EvICx4gMuRJo254hv"
   sc = SlackClient(slack_token)
   sc.api_call(
        "chat.postMessage",
        channel="#engops-notifications",
        text=impactTable,
        type= "message",
   )
