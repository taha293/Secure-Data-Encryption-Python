import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os
import time

if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
f = Fernet(st.session_state.KEY)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "attempt" not in st.session_state:
    st.session_state.attempt = 3
if "timeout" not in st.session_state:
    st.session_state.timeout = 0


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
        try:
            token_bytes = bytes.fromhex(token) 
            if token_bytes in stored_data:
                salt = stored_data[token_bytes]["salt"]
                validate_passkey = hashlib.pbkdf2_hmac('sha256', salt, passkey.encode(), 100000)
                if stored_data[token_bytes]['passkey'] == validate_passkey:
                    return f.decrypt(token_bytes).decode() 
                else:
                    return False
            else:
                return False
        except ValueError:
            return False
        except KeyError:
            return False


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
    now = time.time()
    if now < st.session_state.timeout:
        remaining_time = int(st.session_state.timeout - now)
        st.warning(f"Too many failed attempts. Locked for {remaining_time} seconds.")
        st.stop()
    if st.button('🗂 Decrypt Data'):
        validate = validate_data(st.session_state.stored_data,token_r,passkey_r)
        if validate:
            st.success("Decrypted Successfully")
            st.info(validate)
        else:
            st.session_state.attempt = st.session_state.attempt - 1
            if st.session_state.attempt == 0:
                st.session_state.timeout = now + 30
                st.session_state.attempt = 3
            else:
                st.error(f'Failed: You have {st.session_state.attempt} Attempts left')