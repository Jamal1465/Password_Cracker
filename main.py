import  os
import sys
import time
import string
import io
import logging
import requests
import threading
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed

import msoffcrypto
import pyzipper
import PyPDF2
import colorama
from tqdm import tqdm
from tabulate import tabulate
import  tkinter as tk
from tkinter import filedialog,ttk, messagebox,scrolledtext
from PIL import ImageTk, Image

# initialize colorma for colored console output
colorama.init()

#Setup Logging config
logging.basicConfig(filename='password-cracking.log',level=logging.INFO, format='%(asctime)s -%(levelname)s  - %(message)s')

#Global Variables
stop_flag=False
result=[]


# Defining utility funtions
def resource_path(relative_path):
    try:
        base_path=sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def try_password(file_path, file_type, password):
    logging.info(f"Trying password:  {password}")
    try:
        if file_type in ["xls", "xlsx", "docx", "doc"]:
            return  try_office_password(file_path,password)
        elif file_type =="zip":
            return  try_zip_password(file_path,password)
        elif file_type == "pdf":
            return try_pdf_password(file_path,password)
        else:
            logging.error(f"Unsupported file type: {file_type}")
            return  False
    except Exception as e:
        logging.error(f"Error trying password '{password}': {e}")
        return False

def try_office_password(file_path,password):
    with open(file_path, 'rb') as f:
        file=msoffcrypto.OfficeFile(f)
        file.load_key(password=password)
        with io.BytesIO() as decrypted:
            file.decrypt(decrypted)
            return  True

def try_zip_password(file_path,password):
    with pyzipper.ZipFile(file_path) as zf:
        zf.extractall(pwd=password.encode("utf-8"))
        return True

def try_pdf_password(file_path,password):
    reader = PyPDF2.PdfFileReader(file_path)
    if reader.isEncrypted:
        reader.decrypt(password)
        reader.pages[0]
        return True
    return False

def attemp_passwords(file_path, file_type,passwords,results,batch_index):
    for password in passwords:
        if try_password(file_path, file_type, password):
            results[batch_index]=(password, "Successful")
        else:
            results[batch_index]=(password, "Unsuccessful")
    return None


def get_file_type(file_path):
    extension = os.path.splitext(file_path)[1].lower()
    if extension  in [".xls",".xlsx"]:
        return "xls"
    elif extension in [".doc",".docx"]:
        return "doc"
    elif extension==".zip":
        return "zip"
    elif extension==".pdf":
        return "pdf"
    else:
        return  None

def read_file_lines(file_path):
    encodings=["utf-8","latin-1","ascii"]
    for encode in encodings:
        try:
            with open(file_path,"r",encoding=encode, errors="ignore") as f:
                return [line.strip() for line in f.readlines()]
        except UnicodeDecodeError:
            continue
    raise  ValueError(f"Failed to decode file {file_path} with tried encodings: {encodings}")


