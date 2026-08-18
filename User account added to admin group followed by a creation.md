Objective: User account added to admin group followed by a creation. 

Platform : Splunk

cron : [0 * * * *]

Suggestion : integrating asset &  identity provide additional visibility 

Description : Logic is developed to identify User account being added to admin group followed by a creation.

Mitre Tactic: TA0004

Mitre Technique: T1078.003





index=windows EventCode IN (4720, 4732) 

| bucket _time as Time span=30m

| eval UserName=case( EventCode=4720, TargetUserName), Target_user_sid=case( EventCode=4720, TargetSid, EventCode=4732, MemberSid) 

| stats values(UserName) as UserName dc(EventCode) as dc_count values(EventCode) as EventCodes, values(SubjectUserName) as Created_or_Added_By, values(Group_Name) as Groups, values(MemberSid) as MemberSID, min(_time) as FirstSeen, max(_time) as LastSeen by Time Computer Target_user_sid

| where dc_count > 1 

| where Target_user_sid=MemberSID

| eval TimeDifference=LastSeen-FirstSeen  

| where TimeDifference<=1800  

| search Groups="Administrators"

| convert ctime(FirstSeen) ctime(LastSeen) ctime(Time)
