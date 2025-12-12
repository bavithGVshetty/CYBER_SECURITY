import streamlit as st
import re 

def check_strength(password):
    score=0
    suggestion=[]
    if len(password)>=8:
        score+=1
    else:
        suggestion.append("Use atleast 8 charactor")

    if re.search(r"[A-Z]",password):
        score+=1
    else:
        suggestion.append("Add Uppercase letters")
    
    if re.search(r"[a-z]",password):
        score+=1
    else:
        suggestion.append("Add Lowercase letters")
    
    if re.search(r"[0-9]",password):
        score+=1
    else:
        suggestion.append("Add Numbers")
    if re.search(r"[!@#$%^&*()?,.|<>]",password):
        score+=1
    else:
        suggestion.append("Add Special letters")
    return score, suggestion


st.title("Password strength Checking: ")
st.write("Enter a password to check How strong it is:")

password=st.text_input("Enter your password",type="password")

if password:
    score,suggestions=check_strength(password)
    st.progress(score/5)

    strength_msg=["Very Weak","Weak","Moderate","Strong","Very Strong","Excellent"]
    st.subheader(f"Strength:{strength_msg[score]}")

    if suggestions:
        st.warning("Suggestoing improve your password")
        for s in suggestions:
            st.write(f" {s}")
    else:
            st.success("Great! Strong password")


