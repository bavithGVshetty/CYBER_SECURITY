import streamlit as st
import json
import requests

API_KEY="d7a0d8299adc02c2e0c2badc72b792dc48e41ddfe2b7df66e7ecc2b1e11db797"
VT_URL="https://www.virustotal.com/api/v3/urls"

# Create a funtion
def scan_url(url):
    headers={"x-apikey":API_KEY}
    data ={"url":url}
    response=requests.post(VT_URL,headers=headers,data=data)
    analyse_id=response.json()["data"]["id"]

    analyse_url=f"https://www.virustotal.com/api/v3/analyses/{analyse_id}"
    result=requests.get(analyse_url,headers=headers).json()

    return result



st.title("Malware and Phishing URL Scanner:")
st.write("Check Malware in the URL")

url_input=st.text_input("Enter a website URL here")

if st.button("Scan This"):
    if url_input:
        st.info("Scanning URL Please Wait..!")
        result=scan_url(url_input)

        stats=result["data"]["attributes"]["stats"]
        malicous=stats.get("malicious",0)      
        suspicious=stats.get("suspicous",0)

        st.subheader("Scan Resuts here:")

        st.write(f"Malicous detected: {malicous}")
        st.write(f"Suspicous detected: {suspicious}")

        if malicous>0 or suspicious >0:
            st.warning("This URL is unsafe")
        else:
            st.success("This URL is safe")
        
        st.json(stats)
    else :
        st.warning("Please Enter valid URL")

