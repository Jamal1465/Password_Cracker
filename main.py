# Section 1: Initial Setup and Imports

import os
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
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from PIL import Image, ImageTk

# Step 1: Initialize colorama for colored console output
colorama.init()

# Step 2: Setup logging configuration
logging.basicConfig(filename='password_cracker.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Step 3: Define global variables
stop_flag = False  # Global flag for stopping the attack
results = []  # Global results list


# Section 2: Utility Functions

# Step 4: Define a function to get the path to bundled resources in PyInstaller
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Step 5: Define a function to try a password on different file types
def try_password(file_path, file_type, password):
    logging.info(f"Trying password: {password}")
    try:
        if file_type in ['xls', 'xlsx', 'doc', 'docx']:
            return try_office_password(file_path, password)
        elif file_type == 'zip':
            return try_zip_password(file_path, password)
        elif file_type == 'pdf':
            return try_pdf_password(file_path, password)
        else:
            logging.error("Unsupported file type.")
            return False
    except Exception as e:
        logging.error(f"Error trying password '{password}': {e}")
        return False

# Step 6: Define a function to try passwords on MS Office files
def try_office_password(file_path, password):
    # Step 6.1: Open the file and attempt to decrypt it using msoffcrypto
    with open(file_path, "rb") as f:
        file = msoffcrypto.OfficeFile(f)
        file.load_key(password=password)
        with io.BytesIO() as decrypted:
            file.decrypt(decrypted)
            return True

# Step 7: Define a function to try passwords on ZIP files
def try_zip_password(file_path, password):
    # Step 7.1: Open the ZIP file and attempt to extract it using pyzipper
    with pyzipper.AESZipFile(file_path) as zf:
        zf.extractall(pwd=password.encode('utf-8'))
        return True

# Step 8: Define a function to try passwords on PDF files
def try_pdf_password(file_path, password):
    # Step 8.1: Open the PDF file and attempt to decrypt it using PyPDF2
    reader = PyPDF2.PdfReader(file_path)
    if reader.is_encrypted:
        reader.decrypt(password)
        reader.pages[0]
        return True
    return False

# Step 9: Define a function for multithreaded password attempts
def attempt_passwords(file_path, file_type, passwords, results, batch_index):
    for password in passwords:
        if try_password(file_path, file_type, password):
            results[batch_index] = (password, "Success")
            return password
        else:
            results[batch_index] = (password, "Unsuccessful")
    return None

# Step 10: Define a function to determine the file type based on the file extension
def get_file_type(file_path):
    extension = os.path.splitext(file_path)[1].lower()
    if extension in ['.xls', '.xlsx']:
        return 'xls'
    elif extension in ['.doc', '.docx']:
        return 'doc'
    elif extension == '.zip':
        return 'zip'
    elif extension == '.pdf':
        return 'pdf'
    else:
        return None

# Step 11: Define a function to read file lines with fallback encoding and error handling
def read_file_lines(file_path):
    encodings = ['utf-8', 'latin-1', 'ascii']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                return [line.strip() for line in f.readlines()]
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Failed to decode file {file_path} with tried encodings.")


# Section 3: UI Update Functions

# Step 12: Define a function to update the progress message
def update_progress(message):
    progress_var.set(message)

# Step 12.1: Define a function to update the main log
def update_log(message):
    output_log.insert(tk.END, message + "\n")
    output_log.see(tk.END)

# Step 12.2: Define a function to update the results log
def update_results_log(message, success=False):
    if success:
        results_log.tag_configure("success", foreground="green")
        results_log.insert(tk.END, message + "\n", "success")
    else:
        results_log.insert(tk.END, message + "\n")
    results_log.see(tk.END)

# Step 12.3: Define a function to update the progress bar and ETA label
def update_progress_bar(current, total, start_time):
    progress_percentage = min(100, (current / total) * 100)
    progress_bar['value'] = progress_percentage
    progress_label.config(text=f"Progress: {progress_percentage:.2f}%")
    elapsed_time = time.time() - start_time
    if current > 0 and current < total:
        estimated_total_time = elapsed_time * total / current
        estimated_remaining_time = estimated_total_time - elapsed_time
        eta_label.config(text=f"Estimated Time Remaining: {int(estimated_remaining_time // 60)} min {int(estimated_remaining_time % 60)} sec")
    elif current >= total:
        eta_label.config(text="Estimated Time Remaining: 0 min 0 sec")
    root.update_idletasks()

# Step 12.4: Define a function to summarize the results and update the log
def summary_results():
    global results
    if results:
        summary_table = tabulate(results, headers=["Attempt", "Password", "Status"], tablefmt="grid")
        update_results_log(f"\nSummary of findings:\n{summary_table}")
        update_progress("Attack stopped and results summarized.")
        logging.info("Attack stopped and results summarized.")

# Step 13: Define a function to clear the attack results and reset the UI
def clear_attack():
    global stop_flag, results
    stop_flag = False
    results = []
    progress_var.set("")
    output_log.delete(1.0, tk.END)
    results_log.delete(1.0, tk.END)
    progress_bar['value'] = 0
    progress_label.config(text="Progress: 0%")
    eta_label.config(text="Estimated Time Remaining: N/A")
    logging.info("Attack cleared.")


# Section 4: Attack Functions

# Step 14: Define the brute force attack function
def brute_force(file_path, file_type, max_length=6, charset=string.ascii_lowercase):
    global results
    try:
        start_time = time.time()
        attempt_counter = 0
        results = []
        total_attempts = sum(len(charset) ** i for i in range(1, max_length + 1))

        with tqdm(total=total_attempts, desc="Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for length in range(1, max_length + 1):
                for attempt in product(charset, repeat=length):
                    if stop_flag:
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    password = ''.join(attempt)
                    attempt_counter += 1
                    if try_password(file_path, file_type, password):
                        end_time = time.time()
                        results.append([attempt_counter, password, "Success"])
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
                    pbar.update(1)
                    results.append([attempt_counter, password, "Unsuccessful"])
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
        start_time = time.time()
        results = []
        attempt_counter = 0

        try:
            passwords = read_file_lines(dictionary_file)
        except FileNotFoundError:
            update_progress(f"Dictionary file '{dictionary_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        total_attempts = len(passwords)
        password_found = False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            with tqdm(total=total_attempts, desc="Dictionary Attack Progress", unit="attempt", dynamic_ncols=True) as pbar:
                for i in range(0, total_attempts, 10):
                    if password_found or stop_flag:
                        break
                    batch = passwords[i:i + 10]
                    future = executor.submit(attempt_passwords, file_path, file_type, batch, results, i)
                    futures.append(future)
                    attempt_counter += len(batch)
                    pbar.update(len(batch))
                    results.extend([[i + j, pw, "Unsuccessful"] for j, pw in enumerate(batch)])
                    table = tabulate(results[-100:], headers=["Attempt", "Password", "Status"], tablefmt="grid")
                    update_log(table)
                    update_progress_bar(attempt_counter, total_attempts, start_time)
                    root.update_idletasks()

                for future in as_completed(futures):
                    password = future.result()
                    if password:
                        password_found = True
                        end_time = time.time()
                        results.append([attempt_counter, password, "Success"])
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
                    attempt_counter += 1
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
        start_time = time.time()
        results = []
        success_logins = []

        try:
            common_passwords = read_file_lines(common_passwords_file)
        except FileNotFoundError:
            update_progress(f"Common passwords file '{common_passwords_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        try:
            usernames = read_file_lines(usernames_file)
        except FileNotFoundError:
            update_progress(f"Usernames file '{usernames_file}' not found.")
            return None
        except ValueError as e:
            update_progress(str(e))
            return None

        attempt_counter = 0
        total_attempts = len(usernames) * len(common_passwords)

        with tqdm(total=total_attempts, desc="Reverse Brute Force Progress", unit="attempt", dynamic_ncols=True) as pbar:
            for password in common_passwords:
                for username in usernames:
                    if stop_flag:
                        update_progress("Process interrupted by user.")
                        logging.info("Process interrupted by user.")
                        summary_results()
                        return None
                    attempt_counter += 1
                    response = requests.post(url, data={'username': username, 'password': password})
                    if 'Dashboard' in response.text:
                        end_time = time.time()
                        results.append([attempt_counter, username, password, "Success", end_time - start_time])
                        success_logins.append((username, password, attempt_counter, end_time - start_time))
                        found_logins.append([attempt_counter, username, password, end_time - start_time])
                        table = tabulate(found_logins, headers=["Attempt", "Username", "Password", "Time Taken"], tablefmt="grid")
                        update_log(f"\nFound Logins:\n{table}")
                        update_results_log(f"Password found: {password} for username: {username}\nTime taken: {end_time - start_time} seconds\nAttempts made: {attempt_counter}", success=True)
                        logging.info(f"Password found: {password} for username: {username}")
                        logging.info(f"Time taken: {end_time - start_time} seconds")
                        logging.info(f"Attempts made: {attempt_counter}")
                    else:
                        results.append([attempt_counter, username, password, "Unsuccessful"])
                    pbar.update(1)
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

# Section 5: GUI Setup Functions

# Step 17: Define a function to update the UI based on the selected attack type
def update_ui():
    attack_type = attack_type_var.get()
    file_type_frame.grid_remove()
    brute_force_frame.grid_remove()
    dictionary_frame.grid_remove()
    reverse_brute_force_frame.grid_remove()

    if attack_type in ['brute_force', 'dictionary']:
        file_type_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    if attack_type == 'brute_force':
        brute_force_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    elif attack_type == 'dictionary':
        dictionary_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")
    elif attack_type == 'reverse_brute_force':
        reverse_brute_force_frame.grid(row=2, column=0, columnspan=3, pady=5, padx=5, sticky="ew")

# Step 18: Define a function to open a file dialog to select a file
def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

# Step 19: Define a function to run the selected attack
def run_attack():
    global stop_flag, results
    stop_flag = False
    results = []
    attack_type = attack_type_var.get()
    file_type = file_type_var.get()

    if attack_type in ['brute_force', 'dictionary']:
        file_path = file_path_entry.get() if attack_type == 'brute_force' else file_path_entry_dict.get()
        if not file_path or not os.path.isfile(file_path):
            update_progress("Invalid file path.")
            return

    if attack_type == 'brute_force':
        try:
            max_length = int(max_length_entry.get())
        except ValueError:
            update_progress("Invalid maximum length. Please enter a numeric value.")
            return
        charset = charset_entry.get() or string.ascii_lowercase
        threading.Thread(target=brute_force, args=(file_path, file_type, max_length, charset)).start()

    elif attack_type == 'dictionary':
        dictionary_file = dictionary_file_entry.get()
        if not dictionary_file or not os.path.isfile(dictionary_file):
            update_progress("Invalid dictionary file path.")
            return
        threading.Thread(target=dictionary_attack, args=(file_path, file_type, dictionary_file)).start()

    elif attack_type == 'reverse_brute_force':
        url = url_entry.get()
        usernames_file = usernames_file_entry.get()
        common_passwords_file = common_passwords_file_entry.get()
        if not url or not usernames_file or not os.path.isfile(usernames_file) or not common_passwords_file or not os.path.isfile(common_passwords_file):
            update_progress("Invalid input. Please ensure all fields are filled correctly.")
            return
        threading.Thread(target=reverse_brute_force, args=(url, usernames_file, common_passwords_file)).start()

# Step 20: Define a function to stop the current attack
def stop_attack():
    global stop_flag
    stop_flag = True
    update_progress("Stopping the attack...")
    summary_results()

# Step 21: Define a function to handle the window closing event
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()


# Section 6: Main GUI Setup and Loop

# Step 22: Initialize the main window
root = tk.Tk()
root.title("Universal Password Cracker")
root.geometry("800x700")

# Step 23: Set the icon for the window
logo = Image.open(resource_path("password-cracking.png"))
logo = logo.resize((64, 64), Image.LANCZOS)
logo = ImageTk.PhotoImage(logo)
root.iconphoto(False, logo)

# Step 24: Create the main frame
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky="nsew")

# Step 25: Configure the styles for the UI components
style = ttk.Style()
style.configure("TLabel", background="#05050F", foreground="#FFD700")
style.configure("TFrame", background="#05050F")
style.configure("TButton", background="black", foreground="red", bordercolor="#009933", focusthickness=3, focuscolor="none")
style.configure("Green.Horizontal.TProgressbar", troughcolor='#151525', background='#00FF00', bordercolor='#05050F')

# Step 26: Add the attack type selection components
attack_type_var = tk.StringVar(value="brute_force")
attack_type_label = ttk.Label(main_frame, text="Select Attack Type:", font=("Courier New", 12))
attack_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
attack_type_menu = ttk.Combobox(main_frame, textvariable=attack_type_var, state="readonly", font=("Courier New", 12))
attack_type_menu['values'] = ("brute_force", "dictionary", "reverse_brute_force")
attack_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")
attack_type_menu.bind("<<ComboboxSelected>>", lambda e: update_ui())

# Step 27: Add the file type selection frame
file_type_frame = ttk.Frame(main_frame, style="TFrame")
file_type_label = ttk.Label(file_type_frame, text="Select File Type:", font=("Courier New", 12))
file_type_label.grid(row=0, column=0, pady=5, padx=5, sticky="w")
file_type_var = tk.StringVar(value="zip")
file_type_menu = ttk.Combobox(file_type_frame, textvariable=file_type_var, state="readonly", font=("Courier New", 12))
file_type_menu['values'] = ("zip", "xls", "doc", "pdf")
file_type_menu.grid(row=0, column=1, pady=5, padx=(0, 5), sticky="w")
file_type_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky="ew")

# Step 28: Add the brute force configuration frame
brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(brute_force_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(brute_force_frame, text="Browse", command=lambda: browse_file(file_path_entry), style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Max Length:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
max_length_entry = ttk.Entry(brute_force_frame, width=10, font=("Courier New", 12), background="#151525", foreground="red")
max_length_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Label(brute_force_frame, text="Charset:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
charset_entry = ttk.Entry(brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
charset_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")

# Step 29: Add the dictionary attack configuration frame
dictionary_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(dictionary_frame, text="File Path:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
file_path_entry_dict = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
file_path_entry_dict.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", command=lambda: browse_file(file_path_entry_dict), style="TButton").grid(row=2, column=2, pady=5, padx=5, sticky="w")
ttk.Label(dictionary_frame, text="Dictionary File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
dictionary_file_entry = ttk.Entry(dictionary_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
dictionary_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(dictionary_frame, text="Browse", command=lambda: browse_file(dictionary_file_entry), style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")

# Step 30: Add the reverse brute force configuration frame
reverse_brute_force_frame = ttk.Frame(main_frame, style="TFrame")
ttk.Label(reverse_brute_force_frame, text="Target URL:", font=("Courier New", 12)).grid(row=2, column=0, pady=5, padx=5, sticky="w")
url_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
url_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Usernames File:", font=("Courier New", 12)).grid(row=3, column=0, pady=5, padx=5, sticky="w")
usernames_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
usernames_file_entry.grid(row=3, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", command=lambda: browse_file(usernames_file_entry), style="TButton").grid(row=3, column=2, pady=5, padx=5, sticky="w")
ttk.Label(reverse_brute_force_frame, text="Common Passwords File:", font=("Courier New", 12)).grid(row=4, column=0, pady=5, padx=5, sticky="w")
common_passwords_file_entry = ttk.Entry(reverse_brute_force_frame, width=40, font=("Courier New", 12), background="#151525", foreground="red")
common_passwords_file_entry.grid(row=4, column=1, pady=5, padx=5, sticky="w")
ttk.Button(reverse_brute_force_frame, text="Browse", command=lambda: browse_file(common_passwords_file_entry), style="TButton").grid(row=4, column=2, pady=5, padx=5, sticky="w")

# Step 31: Add the Run, Stop, and Clear buttons
ttk.Button(main_frame, text="Run", command=run_attack, style="TButton", width=15).grid(row=5, column=0, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Stop", command=stop_attack, style="TButton", width=15).grid(row=5, column=1, pady=10, padx=5, sticky="ew")
ttk.Button(main_frame, text="Clear", command=clear_attack, style="TButton", width=15).grid(row=5, column=2, pady=10, padx=5, sticky="ew")

# Step 32: Create the progress and output display
progress_var = tk.StringVar()
table_var = tk.StringVar()
ttk.Label(main_frame, textvariable=progress_var, wraplength=700, font=("Courier New", 12)).grid(row=6, column=0, columnspan=3, pady=10, padx=10, sticky="ew")
output_frame = ttk.Frame(main_frame, style="TFrame")
output_frame.grid(row=7, column=0, columnspan=3, pady=10, padx=10, sticky="ew")
ttk.Label(output_frame, text="Progress Log:", font=("Courier New", 12)).pack(anchor="w")
output_log = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD, bg="#05050F", fg="#FFD700", font=("Courier New", 10))
output_log.pack(fill=tk.BOTH, expand=True)
ttk.Label(output_frame, text="Results Log:", font=("Courier New", 12)).pack(anchor="w")
results_log = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD, bg="#05050F", fg="#FFD700", font=("Courier New", 10))
results_log.pack(fill=tk.BOTH, expand=True)
progress_bar = ttk.Progressbar(output_frame, orient=tk.HORIZONTAL, length=700, mode='determinate', style="Green.Horizontal.TProgressbar")
progress_bar.pack(fill=tk.X, pady=5)
progress_label = tk.Label(output_frame, text="Progress: 0%", bg="#05050F", fg="#FFD700", font=("Courier New", 12))
progress_label.pack()
eta_label = tk.Label(output_frame, text="Estimated Time Remaining: N/A", bg="#05050F", fg="#FFD700", font=("Courier New", 12))
eta_label.pack()

# Step 33: Set the column configurations
root.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_columnconfigure(2, weight=1)
output_frame.grid_columnconfigure(0, weight=1)

# Step 34: Initialize the UI
update_ui()

# Step 35: Handle the window closing event
root.protocol("WM_DELETE_WINDOW", on_closing)

# Step 36: Start the main loop
root.mainloop()
