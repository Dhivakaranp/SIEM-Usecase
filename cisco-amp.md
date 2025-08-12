# Custom Query to Detect security events  of cisco-amp passthrugh events
` index="cisco-amp"   event.event_type  IN ("Exploit Prevention", "Retrospective Quarantine Attempt Failed","Retrospective Detection", "Threat Detected", "Quarantine Failure","Execution Blocked", "Threat Quarantined","Threat Detection","Cloud IOC") 

| bin span=1h _time 

|  stats count values(file_name) as file_name  values(event.event_type) As Event  count(event.event_type) as EC earliest(_time) as ET earliest(event.event_type) as firstevent latest(_time) as LT  latest(event.event_type) as Lastevent values(signature)  by dest file_hash event.file.disposition  

| rename dest as hostname  

| search NOT Lastevent IN ("Exploit Prevention","Execution Blocked", "Threat Quarantined")   

|  convert ctime(ET) ctime(LT)  

| eval title = "SSM : Endpoint - Cisco-AMP " .Lastevent." on ".hostname   

| eval urgency= high, impact= high `
