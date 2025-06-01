import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog,scrolledtext,messagebox
from PIL import ImageTk, Image
from pygments.styles.dracula import background

root= tk.Tk()
root.title("Password Cracker ")
root.geometry("800x700")


def resource_path(relative_path):
    try:
        base_path=sys._MEIPASS
    except Exception:
        base_path=os.path.abspath(".")
    return  os.path.join(base_path, relative_path)

logo= Image.open(resource_path("password-cracking.png"))
logo=logo.resize((64,64),Image.LANCZOS)
logo=ImageTk.PhotoImage(logo)
root.iconphoto(False,logo)

main_frame= ttk.Frame(root, padding="10")
main_frame.grid(column=0,row=0, sticky="nsew")

style = ttk.Style()
style.configure("TLabel",background="#05050F",foreground="#FFC700")
style.configure("TFrame", background="#05050F")
style.configure("TButton", background="black", foreground="red", focusthickness=3, focuscolor="none")
style.configure("Green.Horizontal.TProgressbar",troughcolor="#151525", background="#00FF00",bordercolor="#05050F")


attack_type_var=tk.StringVar(value="Brute_Force")
attack_type_label=ttk.Label(main_frame,text="Select Attack Type", font=("Courier New",12))
attack_type_label.grid(column=0,row=0,pady=5,padx=5,sticky="w")
attack_type_menu=ttk.Combobox(main_frame, textvariable=attack_type_var, state="readonly", font=("Courier New",12))
attack_type_menu["value"]=("Brute_Force","Dictionary","Reverse_Brute_Force")
attack_type_menu.grid(column=1,row=0,pady=5,padx=(0,5),sticky="w")


file_type_frame= ttk.Frame(main_frame,style="TFrame")
file_type_label=ttk.Label(file_type_frame, text="Select File Type", font=("Courier New",12))
file_type_label.grid(column=0,row=0,pady=5,padx=5,sticky="w")
file_type_var=tk.StringVar(value="zip")
file_type_menu=ttk.Combobox(file_type_frame,textvariable=file_type_var, state="readonly", font=("Courier New",12))
file_type_menu["values"]=("zip", "xls","doc","pdf")
file_type_menu.grid(column=1,row=0,pady=5,padx=(0,5),sticky="w")
file_type_frame.grid(column=0,row=1,columnspan=3 ,pady=5,padx=5,sticky="ew")


brute_force_frame=ttk.Frame(main_frame,style="TFrame")
ttk.Label(brute_force_frame,text="File Path", font=("Courier New",12)).grid(column=0,row=2,pady=5,padx=5,sticky="w")
file_path_entry=ttk.Entry(brute_force_frame,width=40,font=("Courier New",12), background="#151525",foreground="red")
file_path_entry.grid(row=2,column=1,pady=5,padx=5,sticky="w")
ttk.Button(brute_force_frame, text="Browse",style="TButton").grid(column=2,row=2,pady=5,padx=5,sticky="w")
ttk.Label(brute_force_frame,text="Max Length", font=("Courier New ",12)).grid(row=3,column=0,pady=5,padx=5,sticky="w")
max_length_entry=ttk.Entry(brute_force_frame,widget=10,font=("Courier New",12), background="#151525",foreground="red")
max_length_entry.grid(row=3,column=1,pady=5,padx=5,sticky="w")
ttk.Label(brute_force_frame, text="Charset:", font=("Courier New",12)).grid(row=4,column=0,pady=5,padx=5,sticky="w")
charset_entry=ttk.Entry(brute_force_frame, width=40, font=("Courier New",12), background="#151525",foreground="red")
charset_entry.grid(row=4,column=1,pady=5,padx=5,sticky="w")



dictionary_frame = ttk.Frame(main_frame,style="TFrame")
ttk.Label(dictionary_frame, text="File Path:", font=("Courier New",12)).grid(column=0,row=2,pady=5,padx=5,sticky="w")
file_path_entry_dict=ttk.Entry(dictionary_frame,width=40, font=("Courier New",12), background="#151525",foreground="red")
file_path_entry_dict.grid(row=2,column=1,pady=5,padx=5,sticky="w")
ttk.Button(dictionary_frame, text="Browse", style="TButton").grid(column=2,row=2,pady=5,padx=5,sticky="w")
ttk.Label(dictionary_frame, text="Dictionary File", font=("Courier New",12)).grid(column=0,row=3,pady=5,padx=5,sticky="w")
dictionary_file_entry=ttk.Entry(dictionary_frame, width=40, font=("Courier New",12), background="#151525",foreground="red")
dictionary_file_entry.grid(row=3,column=1,pady=5,padx=5,sticky="w")
ttk.Button(dictionary_frame, text="Browse", style="TButton").grid(column=2,row=3,pady=5,padx=5,sticky="w")
