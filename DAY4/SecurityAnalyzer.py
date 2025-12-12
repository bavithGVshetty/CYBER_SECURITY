import streamlit as st
import pandas as pd
import platform
import subprocess
import os

st.title("OS SECURITY ANALYZER")

os_type = platform.system()
st.write(f"Detected OS Type: {os_type}")

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# USER AUDIT
st.subheader("User and Permission Audit")

if os_type == "Windows":
    users = run_cmd("net user")
    admins = run_cmd("net localgroup administrators")

    st.text("=== Users ===")
    st.text(users.stdout)

    st.text("=== Administrators Group ===")
    st.text(admins.stdout)

# FILE PERMISSION AUDIT
st.subheader("File Permission Audit")

if os_type == "Windows":
    folder = st.text_input("Enter folder path to check permissions (Ex: C:\\Windows\\System32)")

    if st.button("Check Permission"):
        try:
            files = os.listdir(folder)
        except Exception as e:
            st.error(f"Error accessing folder: {e}")
            files = []

        data = []

        for f in files[:50]:
            file_path = os.path.join(folder, f)

            try:
                # Fix PowerShell formatting
                cmd = f"Powershell -Command \"(Get-Acl '{file_path}').Access | Format-List\""
                acl_output = run_cmd(cmd).stdout

                if "Everyone" in acl_output and "Allow" in acl_output:
                    status = "Weak Permission (Everyone has access)"
                else:
                    status = "Secure (No issues)"

                data.append({"File": f, "Status": status})

            except Exception:
                pass

        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)

# SECURITY RECOMMENDATIONS
st.subheader("Security Recommendations")

recommendations = []

if os_type == "Windows":

    # Check if Everyone has administrative access
    if "Everyone" in admins.stdout:
        recommendations.append("Remove 'Everyone' from Administrators group.")

    # Check if Guest account exists and is active
    if "Guest" in users.stdout:
        recommendations.append("Disable the Guest account to prevent unauthorized access.")

    if len(recommendations) == 0:
        st.success("System appears secure based on current checks.")
    else:
        for r in recommendations:
            st.error(r)
