import boto3
import numpy as np
from ares import CVESearch
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
      print("Engine version: ",engine_version )
      print("Engine Name: ",engine)
      if( engine == "mysql" ):
         dbvendor=cve.search('oracle/mysql')
         key="cpe:2.3:a:oracle:mysql:"+engine_version
      if( engine == "postgres" ):
         dbvendor=cve.search('postgresql/postgresql')
         key="cpe:2.3:a:postgresql:postgresql:"+engine_version
      print("CVE for: "+key)
      output_dict = [x for x in dbvendor if x['vulnerable_configuration'].count(key)>0]
      print("CVE ID: "+output_dict[0]["id"])
      print("Score "+output_dict[0]["cvss"])
      print("Summary:"+output_dict[0]["summary"])
      print("=====================")
 

