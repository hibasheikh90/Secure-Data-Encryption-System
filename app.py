
# Secure Data Vault App
import streamlit as st
import hashlib
import time
import uuid
import json
import os
import base64
from cryptography.fernet import Fernet
import streamlit.components.v1 as components

# --- Helper Functions ---

# Ye function saved data ko load karta hai JSON file se
def load_data():
    if os.path.exists("data.json"):
        with open("data.json", "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    return {}

# Ye function data ko save karta hai JSON file mein
def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)

# Password ko securely hash karta hai salt ke saath
def hash_passkey(passkey, salt):
    return hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), 100000).hex()

# Unique salt generate karta hai
def generate_salt():
    return str(uuid.uuid4())

# Passkey aur salt se fernet key generate karta hai (encryption key)
def generate_fernet_key_from_passkey(passkey, salt):
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), 100000)
    return Fernet(base64.urlsafe_b64encode(key[:32]))

# Data ko encrypt karta hai
def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

# Data ko decrypt karta hai
def decrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data.encode()).decode()

# --- Pages ---

# Logout function
def logout():
    st.session_state.authorized = False
    st.session_state.current_user = ""
    st.session_state.page = "register"
    st.success("You have been logged out!")

# Registration page
def register_page():
    st.title("🔐 Secure Data Vault Registration")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if username in st.session_state.data_store:
            st.error("Username already exists")
        elif password != confirm_password:
            st.error("Passwords do not match")
        elif len(password) < 8:
            st.error("Password must be at least 8 characters")
        else:
            salt = generate_salt()
            hashed_pass = hash_passkey(password, salt)
            fernet_key = Fernet.generate_key().decode()

            st.session_state.data_store[username] = {
                "password": hashed_pass,
                "salt": salt,
                "fernet_key": fernet_key,
                "entries": {},
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": None
            }
            save_data(st.session_state.data_store)
            st.success("Registration successful! Please log in.")
            st.session_state.page = "login"

# Login page
def login_page():
    st.title("🔐 Secure Data Vault Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = st.session_state.data_store
        if username in users:
            salt = users[username]["salt"]
            hashed_pass = hash_passkey(password, salt)

            if hashed_pass == users[username]["password"]:
                st.session_state.authorized = True
                st.session_state.current_user = username
                st.session_state.page = "home"
                st.session_state.data_store[username]["last_login"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_data(st.session_state.data_store)
                st.success("Login successful!")
            else:
                st.error("Incorrect password")
        else:
            st.error("Username not found")

# Page to store encrypted data
def store_data_page():
    if not st.session_state.authorized:
        st.warning("Please login to access this page.")
        return

    st.title("🔒 Store Encrypted Data")
    data_title = st.text_input("Title (Optional)")
    data = st.text_area("Your Data")
    passkey = st.text_input("Encryption Key", type="password")
    confirm_passkey = st.text_input("Confirm Key", type="password")

    if st.button("Encrypt & Save"):
        if not data or not passkey:
            st.error("Please enter data and key")
            return
        if passkey != confirm_passkey:
            st.error("Keys do not match")
            return

        try:
            user = st.session_state.current_user
            fernet_key = st.session_state.data_store[user]["fernet_key"]
            encrypted = encrypt_data(data, fernet_key)

            entry_id = str(uuid.uuid4())
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            st.session_state.data_store[user]["entries"][entry_id] = {
                "data": encrypted,
                "title": data_title or "Untitled",
                "created_at": timestamp
            }

            save_data(st.session_state.data_store)

            st.success("Data encrypted and saved successfully!")
            st.code(f"Entry ID: {entry_id}", language="text")

        except Exception as e:
            st.error(f"Encryption error: {e}")

# Page to retrieve data
def retrieve_data_page():
    if not st.session_state.authorized:
        st.warning("Please login to access this page.")
        return

    st.title("🔓 Retrieve Encrypted Data")
    user = st.session_state.current_user
    entries = st.session_state.data_store[user]["entries"]

    if not entries:
        st.warning("No entries found.")
        return

    entry_list = {f"{v['title']} ({v['created_at']})": k for k, v in entries.items()}
    selected = st.selectbox("Select Entry", list(entry_list.keys()))

    if selected:
        entry_id = entry_list[selected]
        entry = entries[entry_id]
        encrypted = entry["data"]

        passkey = st.text_input("Decryption Key", type="password")

        if st.button("Decrypt"):
            try:
                fernet_key = st.session_state.data_store[user]["fernet_key"]
                decrypted = decrypt_data(encrypted, fernet_key)
                st.success("Decryption successful!")
                st.text_area("Decrypted Data", decrypted, height=150)
            except Exception as e:
                st.error(f"Decryption failed: {e}")

# User profile page
def profile_page():
    if not st.session_state.authorized:
        st.warning("Please login.")
        return

    st.title("👤 Profile")
    user = st.session_state.current_user
    data = st.session_state.data_store[user]

    st.markdown(f"""
    **Username:** {user}  
    **Created At:** {data['created_at']}  
    **Last Login:** {data.get("last_login", "N/A")}  
    **Stored Entries:** {len(data["entries"])}
    """)

# Dashboard help/tips
def dashboard_tips():
    st.markdown("### 📊 Dashboard Tips")
    st.markdown("""
    - 💾 Store your encrypted data securely  
    - 📂 Retrieve it only with your key  
    - 👤 Check your profile info anytime  
    """)

# Footer animation
def footer_animation():
    footer_html = """
    <style>
        .footer {
            position: fixed;
            bottom: 10px;
            width: 100%;
            text-align: center;
            font-size: 16px;
            color: #888;
            animation: fadeIn 2s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    </style>
    <div class="footer">
        Developed by <b style="color:#ff4b4b;">💖Code Queen Hiba Sheikh 👑</b>
    </div>
    """
    components.html(footer_html, height=50)

# --- Main App ---
def main():
    if "data_store" not in st.session_state:
        st.session_state.data_store = load_data()
    if "authorized" not in st.session_state:
        st.session_state.authorized = False
    if "current_user" not in st.session_state:
        st.session_state.current_user = ""
    if "page" not in st.session_state:
        st.session_state.page = "register"

    if not st.session_state.authorized:
        if st.session_state.page == "register":
            register_page()
        else:
            login_page()
    else:
        st.sidebar.title(f"Welcome, {st.session_state.current_user}")
        if st.sidebar.button("🏠 Dashboard"):
            st.session_state.page = "home"
        if st.sidebar.button("💾 Store Data"):
            st.session_state.page = "store"
        if st.sidebar.button("📂 Retrieve Data"):
            st.session_state.page = "retrieve"
        if st.sidebar.button("👤 Profile"):
            st.session_state.page = "profile"
        if st.sidebar.button("🚪 Logout"):
            logout()

        if st.session_state.page == "home":
            st.title("🔐 Secure Data Vault Dashboard")
            dashboard_tips()
        elif st.session_state.page == "store":
            store_data_page()
        elif st.session_state.page == "retrieve":
            retrieve_data_page()
        elif st.session_state.page == "profile":
            profile_page()

    footer_animation()  # 👑 Show footer with animation

if __name__ == "__main__":
    main()







