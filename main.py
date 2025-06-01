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
from pygments.styles.dracula import foreground
from tqdm import tqdm
from tabulate import tabulate
import  tkinter as tk
from tkinter import filedialog,ttk, messagebox,scrolledtext
from PIL import ImageTk, Image

from gui import output_log, eta_label

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




def update_progress(message):
    progress_var.set(message)

def update_log(message):
    output_log.insert(tk.END, message+ "\n")
    output_log.see(tk.END)

def update_result_log(message,success=False):
    if success:
        results_log.tag_configure("success", foreground="green")
        results_log.insert(tk.END, message+ "\n", "success")
    else:
        results.log.insert(tk.END, message+ "\n")
    results_log.see(tk.END)

def update_progress_bar(current,total, start_time):
    progress_percentage=min(100, (current/total)*100)
    progress_bar["value"]=progress_percentage
    progress_label.config(text=f"Progress: {progress_percentage:.2f}%")
    elapsed_time=time.time() -start_time
    if current>0 and current<total:
        estimated_total=elapsed_time*total/current
        estimated_remaining_time=estimated_total-elapsed_time
        eta_label.config(text=f"Estimated Time Remaining:int(estimated_remaining_time//60) min int(estimated_remaining_time%60) sec")
    elif current >=total:
        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
    root.update_idletasks()


def summary_results():
    global results
    if results:
        summary_table= tabulate(results, headers=["Attempt","Password","Status"],tablefmt="grid")
        update_result_log(f"\nSummary of findings:\n {summary_table}")
        update_progress("Attack stopped and results summarized.")
        logging.info("Attack stopped and results summarized.")


def clear_attack():
    global stop_flag, results
    stop_flag = False
    results=[]
    progress_var.set("")
    output_log.delete("1.0",tk.END)
    results_log.delete("1.0",tk.END)
    progress_bar["value"]=0
    progress_label.config(text="Progress: 0%")
    eta_label.config(text="Estimated Time Remaining: N/A ")
    logging.info("Attack cleared")


def brute_force(file_path, file_type, max_length=6, charset=string.ascii_lowercase):
    global results
    try:
        start_time = time.time()  # Record the start time
        attempt_counter = 0  # Initialize the attempt counter
        results = []  # Initialize the results list
        total_attempts = sum(len(charset) ** i for i in range(1, max_length + 1))  # Calculate total attempts

        with tqdm(total=total_attempts, desc="Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for length in range(1, max_length + 1):  # Loop through each password length
                for attempt in product(charset, repeat=length):  # Generate all combinations of the given length
                    if stop_flag:  # Check if the stop flag is set
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    password = ''.join(attempt)  # Join the characters to form a password
                    attempt_counter += 1  # Increment the attempt counter
                    if try_password(file_path, file_type, password):  # Try the generated password
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, password, "Success"])  # Append successful attempt
                        table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
                        update_log(table)
                        update_results_log(f"Password found: {password} for file: {file_path}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                        update_progress_bar(total_attempts, total_attempts, start_time)
                        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
                        root.update_idletasks()
                        return password
                    pbar.update(1)  # Update the progress bar
                    results.append([attempt_counter, password, "Unsuccessful"])  # Append unsuccessful attempt
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()
        update_results_log("Password not found.")
        logging.info("Password not found.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None

# Step 15: Define the dictionary attack function
def dictionary_attack(file_path, file_type, dictionary_file):
    global results
    try:
        start_time = time.time()  # Record the start time
        results = []  # Initialize the results list
        attempt_counter = 0  # Initialize the attempt counter

        try:
            passwords = read_file_lines(dictionary_file)  # Read passwords from dictionary file
        except FileNotFoundError:
            update_progress(f"Dictionary file '{dictionary_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        total_attempts = len(passwords)  # Calculate total attempts
        password_found = False  # Initialize the password found flag

        with ThreadPoolExecutor(max_workers=10) as executor:  # Create a thread pool
            futures = []
            with tqdm(total=total_attempts, desc="Dictionary Attack Progress", unit="attempt", dynamic_ncols=True) as pbar:
                for i in range(0, total_attempts, 10):  # Process passwords in batches of 10
                    if password_found or stop_flag:
                        break
                    batch = passwords[i:i + 10]
                    future = executor.submit(attempt_passwords, file_path, file_type, batch, results, i)
                    futures.append(future)
                    attempt_counter += len(batch)  # Increment the attempt counter by batch size
                    pbar.update(len(batch))  # Update the progress bar
                    results.extend([[i + j, pw, "Unsuccessful"] for j, pw in enumerate(batch)])  # Append unsuccessful attempts
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

                for future in as_completed(futures):  # Check results of futures
                    password = future.result()
                    if password:
                        password_found = True  # Set password found flag
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, password, "Success"])  # Append successful attempt
                        table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
                        update_log(table)
                        update_results_log(f"Password found: {password} for file: {file_path}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                        update_progress_bar(total_attempts, total_attempts, start_time)
                        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
                        root.update_idletasks()
                        return password
                    if stop_flag:
                        summary_results()
                        return None
                    attempt_counter += 1  # Increment the attempt counter
                    pbar.set_postfix({"Attempts": attempt_counter})
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

        update_results_log("Password not found.")
        logging.info("Password not found.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None

# Step 16: Define the reverse brute force attack function
def reverse_brute_force(url, usernames_file, common_passwords_file):
    global results
    found_logins = []
    try:
        start_time = time.time()  # Record the start time
        results = []  # Initialize the results list
        success_logins = []  # Initialize the success logins list

        try:
            common_passwords = read_file_lines(common_passwords_file)  # Read common passwords
        except FileNotFoundError:
            update_progress(f"Common passwords file '{common_passwords_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        try:
            usernames = read_file_lines(usernames_file)  # Read usernames
        except FileNotFoundError:
            update_progress(f"Usernames file '{usernames_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        attempt_counter = 0  # Initialize the attempt counter
        total_attempts = len(usernames) * len(common_passwords)  # Calculate total attempts

        with tqdm(total=total_attempts, desc="Reverse Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for password in common_passwords:
                for username in usernames:
                    if stop_flag:
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    attempt_counter += 1  # Increment the attempt counter
                    response = requests.post(url, data={'username': username, 'password': password})  # Send login request
                    if 'Dashboard' in response.text:
                        end_time = time.time()  # Record the end time
                        results.append([attempt_counter, username, password, "Success", end_time - start_time])  # Append successful attempt
                        success_logins.append((username, password, attempt_counter, end_time - start_time))  # Append successful login
                        found_logins.append([attempt_counter, username, password, end_time - start_time])  # Append found login
                        table = tabulate(found_logins, headers=["Attempt", "Username", "Password", "Time Taken"], tablefmt="grid")
                        update_log(f"\nFound Logins:\n{table}")
                        update_results_log(f"Password found: {password} for username: {username}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password} for username: {username}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                    else:
                        results.append([attempt_counter, username, password, "Unsuccessful"])  # Append unsuccessful attempt
                    pbar.update(1)  # Update the progress bar
                    table = tabulate(results[-100:], headers=["Attempt", "Username", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

        if success_logins:
            summary_table = tabulate(success_logins, headers=["Username", "Password", "Attempt", "Time Taken"], tablefmt="grid")
            update_results_log(f"\nSummary of found logins:\n{summary_table}")
            logging.info("Summary of found logins:\n" + summary_table)
        else:
            update_results_log("Password not found for any username.")
            logging.info("Password not found for any username.")
        update_progress_bar(total_attempts, total_attempts, start_time)
    except KeyboardInterrupt:
        update_progress("Process interrupted by user.")
        logging.info("Process interrupted by user.")
        summary_results()
    return None
