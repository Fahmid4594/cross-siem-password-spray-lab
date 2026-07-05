import csv 

failed_attempts = {}

with open("data/auth_events.csv",'r') as  file:
    reader = csv.DictReader(file)

    

    for row in reader:
        ip = row['source_ip']
        user = row['username']
        action = row['action']
        if action == "Failed":
            if ip not in failed_attempts:
                failed_attempts[ip] = set()
            
            failed_attempts[ip].add(user)
        elif action == "Success":
        
            if ip in failed_attempts:
                if len(failed_attempts[ip]) > 5:
                    print(f"[CRITICAL] Potential Account Compromise: IP {ip} authenticated as {user} following excessive failed attempts.")



