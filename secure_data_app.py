import streamlit as st
import hashlib
from cryptography.fernet import Fernet


import streamlit as st
import hashlib
from cryptography.fernet import Fernet


KEY = Fernet.generate_key()
cipher = Fernet(KEY)

stored_data = {}  # In-memory data store
failed_attempts = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for data_key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None


st.sidebar.title("Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Go to", menu)


if choice == "Home":
    st.title(" Secure Data Encryption System")
    st.write("Use this app to store and retrieve confidential data securely using passkeys.")


elif choice == "Store Data":
    st.header(" Store Your Data Securely")
    user_data = st.text_area("Enter data to store:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success(" Data encrypted and stored successfully!")
        else:
            st.error(" Please enter both data and a passkey.")


elif choice == "Retrieve Data":
    st.header(" Retrieve Your Encrypted Data")
    encrypted_input = st.text_area("Enter the encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success(f" Decrypted Data: {result}")
            else:
                st.error(f" Incorrect passkey. Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning(" Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error(" Please fill both fields.")


elif choice == "Login":
    st.header(" Reauthorization Required")
    login_password = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_password == "admin123":
            failed_attempts = 0
            st.success(" Reauthorized. Go back to Retrieve Data.")
        else:
            st.error(" Incorrect master password.")
