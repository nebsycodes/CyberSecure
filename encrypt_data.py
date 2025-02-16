from cryptography.fernet import Fernet
from docx import Document
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Function to generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data.encode()).decode()

# Function to read a Word document
def read_word_document(file_path):
    doc = Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return '\n'.join(full_text)

# Function to save encrypted data to a file
def save_encrypted_data(file_path, encrypted_data):
    with open(file_path, 'w') as file:
        file.write(encrypted_data)

# Define keys for different roles from environment variables
role_keys = {
    "admin": os.getenv("ADMIN_KEY"),
    "doctor": os.getenv("DOCTOR_KEY"),
    "nurse": os.getenv("NURSE_KEY")
}

def encrypt_data_for_role(data, role):
    key = role_keys.get(role)
    if key:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()
    raise ValueError("Invalid role")

def decrypt_data_for_role(data, role):
    key = role_keys.get(role)
    if key:
        fernet = Fernet(key)
        return fernet.decrypt(data.encode()).decode()
    raise ValueError("Invalid role")