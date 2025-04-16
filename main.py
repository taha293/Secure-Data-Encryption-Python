import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

KEY = Fernet.generate_key()
f = Fernet(KEY)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}


def store_data(data,key):
    salt = os.urandom(16)
    data_token = f.encrypt(data.encode())
    data_passkey = hashlib.pbkdf2_hmac('sha256',salt,key.encode(),100000)
    st.session_state.stored_data[data_token] = {
        "passkey":data_passkey,
        "salt":salt
        }
    return data_token

def validate_data(stored_data,token,passkey):
    token_b = bytes.fromhex(token)
    salt = stored_data[token_b]["salt"]
    valiadate_passkey = hashlib.pbkdf2_hmac('sha256',salt,passkey.encode(),100000)
    if stored_data[token_b]['passkey'] == valiadate_passkey:
        return 

# Streamlit 

st.set_page_config(page_title="Secure Data App", page_icon="🔐")

with st.sidebar:
    st.write("#### **🔒 Secure Data Encryption System**")
    menu = st.radio("Navigate: ", ["🏠 Home","💾 Store Data","📂 Retrieve Data"])

st.header(menu)
if menu == "🏠 Home":
    st.subheader("🔐 Welcome to Secure Data Storage")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("#### **Account Access and Data Management:**")
    st.write('💾**Encrypted Storage:**')
    st.write('Safeguard your confidential information through robust encryption methods.')
    st.write('📂**Data Control:**')
    st.write('Easily access, manage, or remove your stored data whenever required.')

elif menu == "💾 Store Data":
    data = st.text_area("📥 Enter data to store")
    passkey = st.text_input("🔑 Enter passkey")
    if st.button("💾 Encrypt and Save"):
        token = store_data(data,passkey)
        st.success("Data encrypted and stored. Copy passkey given below for retrieve your data.")
        st.code(token.hex(),language='text')

elif menu == "📂 Retrieve Data":
    token_r = st.text_input("📥 Enter data token")
    passkey_r = st.text_input("🔑 Enter passkey", type='password')
    if st.button('🗂 Decrypt Data'):
        validate = validate_data(st.session_state.stored_data,token_r,passkey_r)
        if validate:
            st.success('Yay')