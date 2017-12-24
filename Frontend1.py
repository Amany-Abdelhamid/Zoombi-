from socket import *


def Start_Sniffing():
    sniff()

#********** trivial function for check *********

def dou(s):
    print("ok")


def exit():
    root.quit()

def raise_frame(frame):
    frame.tkraise()


def start_button_functions(f22):
    raise_frame(f22)
    Start_Sniffing()

def Stop_Sniffing():
    root.after_cancel(AFTER)
    print("stop sniffing=============================================================")
    start_button['state'] = 'normal'
    restart_button['state'] = 'normal'
    stop_button['state'] = 'disable'



root = Tk()
# * *********** create two main frames and switch between them ****************

f1 = Frame(root)
f2 = Frame(root)
for frame in (f1, f2):
    frame.grid(row=0, column=0, ipadx=9.5, sticky='news')
# ********menubar************

menu = Menu(root)
filemenu = Menu(menu)
menu.add_cascade(label="File", menu=filemenu)
filemenu.add_command(label="OPEN", command=dou)
filemenu.add_command(label="SAVE", command=dou)
filemenu.add_separator()
filemenu.add_command(label="EXIT", command=exit)
root.config(menu=menu)
toolbar = Frame(f1, bd=1, relief=RAISED)
start = PhotoImage(file="start.png")
start_button = Button(toolbar, image=start, state=NORMAL, command=lambda: start_button_functions(f2))
start_button.photo1 = start
start_button.pack(side=LEFT, padx=1, pady=1)
toolbar.pack(fill=X)
stop = PhotoImage(file="stop.png")
stop_button = Button(toolbar, image=stop, state=DISABLED)
stop_button.photo2 = stop
stop_button.pack(side=LEFT, padx=1, pady=1)
restart = PhotoImage(file="restart.png")
restart_button = Button(toolbar, image=restart, state=DISABLED)
restart_button.photo3 = restart
restart_button.pack(side=LEFT)

# *********************displaybar******************

display_bar = Frame(f1, bd=1, relief=RAISED)
combo = ttk.Combobox(display_bar, text="Apply a display filter")
combo['values'] = ('http', 'tcp')
display_bar.pack(fill=X)
combo.pack(side=TOP, fill=X)
combo.bind("<<ComboboxSelected>>", dou)
# ***********************capture frame ****************

capture_frame = Frame(f1, bd=1, relief=RAISED)
label_capture = Label(capture_frame, text="Capture")
label_using = Label(capture_frame, text="using this filter:")
combo2 = ttk.Combobox(capture_frame, text="Enter a capture filter")
combo2['values'] = ('http', 'tcp')
capture_frame.pack(side=TOP, fill=X)
label_capture.pack(side=TOP)
label_using.pack(side=LEFT)
combo2.pack(side=TOP, fill=X)
combo.bind("<<ComboboxSelected>>", dou)
# **********************8listbox**********************
lb_frame = Frame(f1, bd=1, relief=RAISED)
lb = Listbox(lb_frame, selectmod=SINGLE)
lb.insert(1, "WIFI")
lb.insert(2, "Ethernet")
lb.bind('<Double-1>', lambda x: start_button_functions(f2))
lb_frame.pack(side=TOP, fill=X)
lb.pack(side=TOP, fill=BOTH, ipady=212)
# *****************toolbar of frame 2****************

toolbar = Frame(f2, bd=1, relief=RAISED)
start = PhotoImage(file="start.png")
start_button = Button(toolbar, image=start, state=DISABLED, command=lambda: Start_Sniffing())
start_button.photo1 = start
start_button.pack(side=LEFT, padx=1, pady=1)
toolbar.pack(fill=X)
stop = PhotoImage(file="stop.png")
stop_button = Button(toolbar, image=stop, state=NORMAL, command=lambda: Stop_Sniffing())
stop_button.photo2 = stop
stop_button.pack(side=LEFT, padx=1, pady=1)
restart = PhotoImage(file="restart.png")
restart_button = Button(toolbar, image=restart, state=DISABLED, command=lambda: Start_Sniffing())
restart_button.photo3 = restart
restart_button.pack(side=LEFT)

# ***********************display bar of frame 2 ***************

display_bar = Frame(f2, bd=1, relief=RAISED)
combo = ttk.Combobox(display_bar, text="Apply a display filter")
combo['values'] = ('http', 'tcp')
display_bar.pack(fill=X)
combo.pack(side=TOP, fill=X)
combo.bind('<Button-1>', dou)
combo.bind("<<ComboboxSelected>>", dou)
raise_frame(f1)
root.mainloop()