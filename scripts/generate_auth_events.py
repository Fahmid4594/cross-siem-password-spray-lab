import csv
import os
from faker import Faker
from datetime import datetime, timedelta
import random

os.makedirs("data",exist_ok=True)

fake = Faker()

event_header = ["time_stamp","username","source_ip","event_id","action"]

all_events = []



attack_time = datetime(2026,7,1,10,0,0)
attacker_ip = "185.22.44.10"
for i in range(25):
        attack_time += timedelta(seconds=random.randint(12,34))
        time_stamp = attack_time
        username = fake.user_name()
        source_ip = attacker_ip
        event_id = 4625
        action ="Failed"
        all_events.append([time_stamp,username,source_ip,event_id,action])
    
attack_time += timedelta(seconds=random.randint(24,68))
success_event_id = 4624
attacker_username = fake.user_name()
action ="Success"
    
all_events.append([attack_time,attacker_username,attacker_ip,success_event_id,action])

fp1_time = fake.date_time_this_month()
fp1_user = fake.user_name()
fp1_ip = fake.ipv4()

for i in range(4):
    fp1_time += timedelta(seconds=random.randint(2,6))
    all_events.append([fp1_time,fp1_user,fp1_ip,4625,"Failed"])

fp1_time += timedelta(seconds=random.randint(5,10))
all_events.append([fp1_time,fp1_user,fp1_ip,4624,"Success"])
    



base_time = fake.date_time_this_month()
user_name = "svc_sql_sync"
fp_ip = fake.ipv4()


for i in range(30):
    base_time += timedelta(minutes=24)
    all_events.append([base_time,user_name,fp_ip,4625,"Failed"])


fp3_time = fake.date_time_this_month()
fp3_username = fake.user_name()
fp3_ip = fake.ipv4()

for i in range(24):
    fp3_time += timedelta(hours=1)
    all_events.append([fp3_time,fp3_username,fp3_ip,4625,"Failed"])

fp4_time = fake.date_time_this_month()
fp4_username = "app_server_01"
fp4_ip = fake.ipv4_private()

for i in range(8):
     fp4_time += timedelta(seconds=random.randint(1,2))
     all_events.append([fp4_time,fp4_username,fp4_ip,4625,"Failed"])

      
    

for i in range(1407):
        time_stamp = fake.date_time_this_month()
        username = fake.user_name()
        source_ip = fake.ipv4()
        event_id = 4624
        action = "Success"
        all_events.append([time_stamp,username,source_ip,event_id,action])



all_events.sort(key=lambda x: x[0])
        
with open ("data/auth_events.csv",'w',newline="") as file:
    writer = csv.writer(file)
    writer.writerow(event_header)

    for event in all_events:
        writer.writerow(event)