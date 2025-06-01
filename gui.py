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


