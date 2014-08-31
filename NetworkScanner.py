"""
NetworkScanner.py is a small, platform independent desktop application for scanning top 10 most usable ports on remote hosts.
Application is developed for passing college laboratory exercises.
NetworkScanner.py is developed under GNU General Public License, and it is free to sharing.
New extended version of application is considered using PyQt framework.
"""

__author__ = "Zvonimir Susac"
__copyright__ = "Copyright 2014, NetworkScanner Project"
__credits__ = ["Marko Milicici", "Filip Hanzek", "Josip Rotim", "Damir Blazevic"]
__license__ = "GNU GPLv3"
__version__ = "1.0"
__maintainer__ = "Zvonimir Susac"
__email__ = "zsusac@etfos.hr"
__status__ = "Production"

from Tkinter import *
import tkFileDialog
import socket
from datetime import datetime
from time import gmtime, strftime
from PIL import Image, ImageTk
import webbrowser
import threading

""" Funckija scan() pokrece se prilikom pritiska tipke scan. Funckija skenira oznacene portove i ispisuje pripadajucu poruku """
def scan():

    count = 0
    tekst_widget.config(state=NORMAL)
    port_list = []

    try:
        HTTP_port = int(varHTTP.get())
        port_list.append(HTTP_port)
    except ValueError:
        pass
    try:
        SMTP_port = int(varSMTP.get())
        port_list.append(SMTP_port)
    except ValueError:
        pass
    try:
        HTTPS_port = int(varHTTPS.get())
        port_list.append(HTTPS_port)
    except ValueError:
        pass
    try:
        DNS_port = int(varDNS.get())
        port_list.append(DNS_port)
    except ValueError:
        pass
    try:
        FTP_port = int(varFTP.get())
        port_list.append((FTP_port))
    except ValueError:
        pass
    try:
        POP3_port = int(varPOP3.get())
        port_list.append(POP3_port)
    except ValueError:
        pass
    try:
        PPTP_port = int(varPPTP.get())
        port_list.append(PPTP_port)
    except ValueError:
        pass
    try:
        RDP_port = int(varRDP.get())
        port_list.append(RDP_port)
    except ValueError:
        pass
    try:
        SSH_port = int(varSSH.get())
        port_list.append(SSH_port)
    except ValueError:
        pass
    try:
        TELNET_port = int(varTELNET.get())
        port_list.append(TELNET_port)
    except ValueError:
        pass

    timestring = strftime("%a,\n%d %b %Y %H:%M:%S \n", gmtime())
    tekst_widget.insert(INSERT, "Starting NetworkScanner 1.3 at ", '<1>', timestring)  #nest mjenjo
    host_target = varTarget.get()
    tekst_widget.insert(INSERT, "Scanning ", '<1>', host_target)

    if host_target.find('.') >= 0:
        name = socket.gethostname()
    else:
        name = socket.gethostbyaddr(socket.gethostname())

    tekst_widget.insert(INSERT, "\nInitiator ", '<1>', name)

    try:
        host_target_IP = socket.gethostbyname(host_target)
        tekst_widget.insert(INSERT, "\nTarget IP ", '<1>', host_target_IP)
        tekst_widget.insert(INSERT, "\n\n")
        t1 = datetime.now()

        for port in port_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host_target_IP, port))
            if result == 0:
                tekst_widget.insert(INSERT, "Port {}: \t Open".format(port) + "\n")
                count += 1
                sock.close()

        if count == 0:
            tekst_widget.insert(INSERT, "Host not responding\n")
        else:
            pass

        t2 = datetime.now()
        total = t2 - t1
        string_total = str(total)
        tekst_widget.insert(INSERT, '\nScanning Completed in: ' + string_total + "\n \n")
        tekst_widget.config(state=DISABLED)

    except socket.gaierror:
        tekst_widget.config(state=NORMAL)
        tekst_widget.insert(INSERT, 'Hostname could not be resolved.')
        tekst_widget.config(state=DISABLED)
    except UnboundLocalError:
        tekst_widget.config(state=NORMAL)
        tekst_widget.insert(INSERT, 'Hostname could not be resolved.')
        tekst_widget.config(state=DISABLED)
    except socket.error:
        tekst_widget.config(state=NORMAL)
        tekst_widget.insert(INSERT, "Couldn't connect to server")
        tekst_widget.config(state=DISABLED)


"""
Funkcija scan() se pokrece u novoj niti da se glavni prozor aplikacije ne smrzne prilikom napornijeg rada. Ali to bas i nije pomoglo
Tkinter biblioteka je jako ogranicena. Razmatra se nova verzija aplikacije koristenjem PyQt frameworka
"""
def scanT():
    t1 = threading.Thread(target=scan)
    t1.start()
    t1.join()


"""Funkcija clear() pokrece se prilikom pritiska tipke Clear. Brise tekst u tekst_widget """
def clear():
    tekst_widget.config(state=NORMAL)
    tekst_widget.delete('1.0', END)
    tekst_widget.config(state=DISABLED)


"""Funkcija new() koja resetira target_entry_widget, tekst_widget i checkboxeve"""
def new():
    target_entry_widget.delete(0, END)
    tekst_widget.config(state=NORMAL)
    tekst_widget.delete('1.0', END)
    tekst_widget.config(state=DISABLED)
    check_button_HTTP.deselect()
    check_button_HTTPS.deselect()
    check_button_FTP.deselect()
    check_button_SSH.deselect()
    check_button_SMTP.deselect()
    check_button_DNS.deselect()
    check_button_RDP.deselect()
    check_button_TELNET.deselect()
    check_button_PPTP.deselect()
    check_button_POP3.deselect()


"""Funkcija save() koja save-a tekst_widget u txt format na defaultnu lokaciju"""
def save():
    text_from_tekst_widget = tekst_widget.get('1.0', END)
    with open("PortInfo.txt", 'a') as f:
        f.write(text_from_tekst_widget)


"""Funkcija saveas(), mozemo mjenjat ime i lokaciju spremanja, defaultna ekstenzija .txt"""
def saveas():
    f = tkFileDialog.asksaveasfile(mode='w', defaultextension=".txt", title="Save the scan as...")
    if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
        return
    textoutput = tekst_widget.get(0.0, END)
    f.write((unicode(textoutput)))
    f.write("\n")


"""Funckija copy() kopira sadrzaj tekst_widget u clipboard """
def copy():
    root.clipboard_clear()
    copy_text = tekst_widget.get('1.0', END)
    root.clipboard_append(copy_text)


"""Funkcija cut() kopira sadrzaj tekst_widget u clipboard te ga brise"""
def cut():
    root.clipboard_clear()
    copy_text = tekst_widget.get('1.0', END)
    root.clipboard_append(copy_text)
    tekst_widget.config(state=NORMAL)
    tekst_widget.delete('1.0', END)
    tekst_widget.config(state=DISABLED)


"""Funckija about() prikazuje mali prozor s osnovnim informacijama o aplikaciji"""
def about():
    top = Toplevel()
    top.title("About this application...")
    img = ImageTk.PhotoImage(Image.open('Scan.png'))
    panel = Label(top, image=img)
    panel.image = img
    panel.pack(side="top", fill="both", expand="yes")
    about_text = "NetworkScanner 1.0\n\nVersion:\t1.0\nLatest Version:\t1.0\nRelease Date:\t8/15/2014\nLicense Type:\tGNU GPLv3\nCrafted by:\tZvonimir"
    msg = Message(top, text=about_text)
    msg.pack()
    button = Button(top, text="Dismiss", command=top.destroy)
    button.pack()


"""Funkcija reference_manual() otvara browser i prikazuje upute za koristenje programa"""
def reference_manual():
    webbrowser.open("http://www.scribd.com/doc/238241400/KORISNI%C4%8CKE-UPUTE")


"""Funkcija menu() definira menu u glavnom prozoru aplikacije"""
def menu(win):
    top = Menu(win)
    win.config(menu=top)
    file = Menu(top)
    file.add_command(label='New', command=new, underline=0)
    file.add_command(label='Save', command=save, underline=0)
    file.add_command(label='Save as...', command=saveas, underline=0)
    file.add_separator()
    file.add_command(label="Exit", command=root.quit)
    top.add_cascade(label='File', menu=file, underline=0)
    edit = Menu(top)
    edit.add_command(label='Cut', command=cut, underline=0)
    edit.add_command(label='Copy', command=copy, underline=0)
    top.add_cascade(label='Edit', menu=edit, underline=0)
    helpmenu = Menu(top)
    helpmenu.add_command(label="Reference manual", command=reference_manual, underline=0)
    helpmenu.add_command(label="About...", command=about, underline=0)
    top.add_cascade(label="Help", menu=helpmenu, underline=0)


"""Glavna ulazna funckija"""
if __name__ == "__main__":
    root = Tk()
    menu(root)
    root.title('NetworkScanner')

    #Label target_label_widget i Entry target_entry_widget) u koji unosimo naziv ili IP mete (npr. google.hr ili 192.168.1.10)
    target_label_widget = Label(root, text='Target:')
    target_label_widget.grid(row=0, column=0)
    varTarget = StringVar()
    target_entry_widget = Entry(root, bd=1, textvariable=varTarget)
    target_entry_widget.grid(row=0, column=1)

    #Groupbox u kojem su portovi
    group = LabelFrame(root, text="Ports", padx=5, pady=5)
    group.grid(row=1, columnspan=2)

    #Checkbox-evi koji sadrze portove
    varHTTP = StringVar()
    check_button_HTTP = Checkbutton(group, text="HTTP", variable=varHTTP, onvalue="80", offvalue="")
    check_button_HTTP.grid(row=0, column=0)

    varHTTPS = StringVar()
    check_button_HTTPS = Checkbutton(group, text="HTTPS", variable=varHTTPS, onvalue="443", offvalue="")
    check_button_HTTPS.grid(row=0, column=1)

    varFTP = StringVar()
    check_button_FTP = Checkbutton(group, text="FTP", variable=varFTP, onvalue="21", offvalue="")
    check_button_FTP.grid(row=0, column=2)

    varSSH = StringVar()
    check_button_SSH = Checkbutton(group, text="SSH", variable=varSSH, onvalue="22", offvalue="")
    check_button_SSH.grid(row=0, column=3)

    varSMTP = StringVar()
    check_button_SMTP = Checkbutton(group, text="SMTP", variable=varSMTP, onvalue="25", offvalue="")
    check_button_SMTP.grid(row=0, column=4)

    varDNS = StringVar()
    check_button_DNS = Checkbutton(group, text="DNS", variable=varDNS, onvalue="53", offvalue="")
    check_button_DNS.grid(row=1, column=0)

    varRDP = StringVar()
    check_button_RDP = Checkbutton(group, text="RDP", variable=varRDP, onvalue="3389", offvalue="")
    check_button_RDP.grid(row=1, column=1)

    varTELNET = StringVar()
    check_button_TELNET = Checkbutton(group, text="TELNET", variable=varTELNET, onvalue="23", offvalue="")
    check_button_TELNET.grid(row=1, column=2)

    varPPTP = StringVar()
    check_button_PPTP = Checkbutton(group, text="PPTP", variable=varPPTP, onvalue="1723", offvalue="")
    check_button_PPTP.grid(row=1, column=3)

    varPOP3 = StringVar()
    check_button_POP3 = Checkbutton(group, text="POP3", variable=varPOP3, onvalue="110", offvalue="")
    check_button_POP3.grid(row=1, column=4)

    #Button za skeniranje porta, funkcija skinraj
    button_scan_host = Button(root, text="Scan", command=scanT)
    button_scan_host.grid(row=2, column=0)

    #Button za ciscenje richtextboxa
    button_clear_text = Button(root, text="Clear", command=clear)
    button_clear_text.grid(row=2, column=1)

    #Text za prikaz rezultata
    tekst_widget = Text(root, width=50, state=DISABLED)
    tekst_widget.grid(row=4, columnspan=2)

    root.mainloop()
