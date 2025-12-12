# Lets build custom SIEM tool 
# to parse logs and generate 
# alerts based on predefined rules

import streamlit as st
import pandas as pd
from collections import defaultdict

st.title("Mini SIEM")
st.write("Upload log file or text file to detected suspicoius activity")

uploaded_file=st.file_uploader("Upload log file",type=["txt","log"])

sql_attemps=[]
unauthorized=[]
alerts=[]
failed_logins=defaultdict(int)

if uploaded_file:
    lines=uploaded_file.read().decode().split("\n")

    for line in lines:

        if "Failed password" in line or "4625" in line:
            ip=line.split("from")[-1].split()[0]
            failed_logins[ip]+=1
        
        # SQL injection
        sql_signatures= ["'", "\"", "' OR 1=1--", "\" OR 1=1--", "';", "' OR '1'='1"]

        if any(sig in line for sig in sql_signatures):
            sql_attemps.append(line)

        # Unauthorized access

        if "401" in line or  "403" in line:
            unauthorized.append(line)
        
    for ip,count in failed_logins.items():
        if count>5:
            alerts.append(f"Attack detected from {ip} {count} failed attemps")
            
    if sql_attemps:
        alerts.append("SQL injecttion Attemps detected")
    if unauthorized:
        alerts.append("Unauthorized access attemps found")

    st.subheader("Alerts")

    if alerts:
        for i in alerts:
            st.error(i)
    else:
        st.success("No serious threats detected")
    
    st.subheader("Failed Logins per IP")
    st.write(dict(failed_logins))

    st.subheader("Sql Injection Attemps")
    for i in sql_attemps:
        st.write(i)

    st.subheader("Unathurized Access Attemps")
    for log in unauthorized:
        st.write(log)
    
    