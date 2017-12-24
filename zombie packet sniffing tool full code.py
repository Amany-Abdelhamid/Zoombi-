from socket import *
from tkinter import *
from tkinter import ttk
import struct
import sys
import re
from datetime import datetime


# for check
def dou(s):
    print("ok")


def exit():
    root.quit()

def on_click (e):
    tv4.selection()
    tv4.selection_remove(1)


def raise_frame(frame):
    frame.tkraise()


def start_button_functions(f22):
    raise_frame(f22)
    Start_Sniffing()


# receive a datagram


def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print("An error happened: ")
        sys.exc_info()
    return data[0]


# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    #   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
    #   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
    #   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
    #   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
    #   the 7th bit is empty and shouldn't be analyzed

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
          reliability[R] + tabs + cost[M]
    return TOS


# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
    #   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
    #   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    tabs = '  '
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags


# get protocol: 8 bits
def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()
        return protocol

    else:
        return 'No such protocol.'


def sniff():
    # the public network interface
    HOST = gethostbyname(gethostname())

    # create a raw socket and bind it to the public interface
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind((HOST, 0))

    # Include IP headers
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    # receive all packages
    s.ioctl(SIO_RCVALL, RCVALL_ON)
    # receive a package
    data = receiveData(s)

    # get the IP header (the first 20 bytes) and unpack them
    # B - unsigned char (1)
    # H - unsigned short (2)
    # s - string

    # IP Protocol
    unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_IHL = unpackedData[0]
    version = version_IHL >> 4  # version of the IP
    IHL = version_IHL & 0xF  # internet header length
    TOS = unpackedData[1]  # type of service
    totalLength = unpackedData[2]
    ID = unpackedData[3]  # identification
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]  # time to live
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = inet_ntoa(unpackedData[8])
    destinationAddress = inet_ntoa(unpackedData[9])
    print("An IP packet with the size %i was captured." % (unpackedData[2]))
    print("Raw data: " + str(data))
    print("\nParsed data")
    print("Version:\t\t" + str(version))
    print("Header Length:\t\t" + str(IHL * 4) + " bytes")
    print("Type of Service:\t" + getTOS(TOS))
    print("Length:\t\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
    print("Flags:\t\t\t" + getFlags(flags))
    print("Fragment offset:\t" + str(fragmentOffset))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + getProtocol(protocolNr))
    global VERSION
    global TYPE
    global IDENTIFICATION
    global FRAGMENT
    global TTLL
    global PROTOCOL
    global SOURCE
    global DESTINATION
    global LENGTH
    global CHECK
    global FLAGS
    global HEADERLENGTH
    global SOURCE_PORT
    global DESTINATION_PORT
    global SEQ_NO
    global ACK
    global TCP_HEADER_LENGTH
    global Time
    global Data
    Time = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
    LENGTH = str(totalLength)
    PROTOCOL = getProtocol(protocolNr)
    SOURCE = sourceAddress
    DESTINATION = destinationAddress
    FLAGS = getFlags(flags)
    VERSION = str(version)
    TYPE = getTOS(TOS)
    IDENTIFICATION = str(hex(ID))
    FRAGMENT = str(fragmentOffset)
    TTLL = str(TTL)
    HEADERLENGTH = str(IHL * 4)
    print("Checksum:\t\t" + str(checksum))
    print("Source:\t\t\t" + sourceAddress)
    CHECK = str(checksum)
    print("Destination:\t\t" + destinationAddress)

    # TCP Protocol
    if protocolNr == 6:
        tcp_header = data[20:40]

        # now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        print(" TCP Protocol Information: ")
        print(" ")
        print('Source Port : ' + str(source_port))
        print(' Dest Port : ' + str(dest_port))
        print(' Sequence Number : ' + str(sequence))
        print(' Acknowledgement : ' + str(acknowledgement))
        print(' TCP header length : ' + str(tcph_length))
        print(" ")
        SOURCE_PORT = str(source_port)
        DESTINATION_PORT = str(dest_port)
        SEQ_NO = str(sequence)
        ACK = str(acknowledgement)
        TCP_HEADER_LENGTH = str(tcph_length)

    # getting the data from the packet
    unpacked = ''
    DATA = ''
    for i in range(int(len(data) / 16)):
        unpackedr = struct.unpack('!BBBBBBBBBBBBBBBB', data[i * 16:(i * 16) + 16])
        for j in range(16):
            unpacked = unpacked + '{:02x}'.format(unpackedr[j])
            if int(unpackedr[j]) > 31 and int(unpackedr[j]) < 127:
                DATA += str(chr(int(unpackedr[j])))
            else:
                DATA += '.'

    index = 0
    i = 0
    Data = ''
    hex_string = unpacked
    while hex_string:
        Data += '{:04x}: '.format(index)
        index += 16
        line, hex_string = hex_string[:64], hex_string[64:]
        while line:
            two_bytes, line = line[2:4], line[4:]
            if two_bytes:
                Data += two_bytes + ' '
        Data = Data[:-1] + "   " + DATA[i:i + 16] + '\n'
        i += 16

    Data = str(Data)
    print(Data)

    # disabled promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)

    return totalLength


def Start_Sniffing():
    global COUNTER_TABLE
    stop_button['state'] = 'normal'
    start_button['state'] = 'disable'
    restart_button['state'] = 'disable'
    print("start sniffing+++++++++++++++++++++++++++++++++++++++++++++++")
    global PROTOCOL
    global SOURCE
    global LENGTH
    global FLAGS
    global CHECK
    global SOURCE_PORT
    global DESTINATION_PORT
    global SEQ_NO
    global ACK
    global TCP_HEADER_LENGTH
    global Data
    sniff()
    tv.insert('', COUNTER_TABLE, COUNTER_TABLE, text=COUNTER_TABLE, values=(COUNTER_TABLE, Time, SOURCE, DESTINATION, PROTOCOL, LENGTH))
    tv3.insert('', COUNTER_TABLE, COUNTER_TABLE, text='yy', values=(VERSION, TYPE, IDENTIFICATION, FRAGMENT, TTLL, SOURCE, DESTINATION, LENGTH, HEADERLENGTH, FLAGS, CHECK, SOURCE_PORT,DESTINATION_PORT, SEQ_NO, ACK, TCP_HEADER_LENGTH, Data))
    COUNTER_TABLE += 1

    global AFTER
    AFTER = root.after(50, Start_Sniffing)


def Choose_Row_From_tv(a):
    row = tv.item(tv.selection())
    item = tv.selection()[0]
    print(tv.item(item)['values'][0])
    global ROWID
    ROWID = tv.item(item)['values'][0]
    version = tv3.item(ROWID)['values'][0]
    type_of_service = tv3.item(ROWID)['values'][1]
    Id = tv3.item(ROWID)['values'][2]
    fragmentation = tv3.item(ROWID)['values'][3]
    ttl = tv3.item(ROWID)['values'][4]
    ip_source = tv3.item(ROWID)['values'][5]
    ip_destination = tv3.item(ROWID)['values'][6]
    length = tv3.item(ROWID)['values'][7]
    Header_length = tv3.item(ROWID)['values'][8]
    flag = tv3.item(ROWID)['values'][9]
    checksum = tv3.item(ROWID)['values'][10]
    source_port = tv3.item(ROWID)['values'][11]
    dest_port = tv3.item(ROWID)['values'][12]
    seq = tv3.item(ROWID)['values'][13]
    ack = tv3.item(ROWID)['values'][14]
    tcp_header = tv3.item(ROWID)['values'][15]
    data_hexa = tv3.item(ROWID)['values'][16]
    tv2.set('item1', 'info', version)
    tv2.set('item3', 'info', Id)
    tv2.set('item4', 'info', fragmentation)
    tv2.set('item5', 'info', ttl)
    tv2.set('item6', 'info', ip_source)
    tv2.set('item7', 'info', ip_destination)
    tv2.set('item8', 'info', length)
    tv2.set('item9', 'info', Header_length)
    tv2.set('item10', 'info', flag)
    tv2.set('item11', 'info', checksum)
    tv2.set('item13', 'info', source_port)
    tv2.set('item14', 'info', dest_port)
    tv2.set('item15', 'info', seq)
    tv2.set('item16', 'info', ack)
    tv2.set('item17', 'info', tcp_header)
    tv4.set(1, 'info', data_hexa)


def Stop_Sniffing():
    root.after_cancel(AFTER)
    print("stop sniffing=============================================================")
    start_button['state'] = 'normal'
    restart_button['state'] = 'normal'
    stop_button['state'] = 'disable'


root = Tk()
VERSION = None
TYPE = None
IDENTIFICATION = 0
FRAGMENT = None
TTLL = None
AFTER = None
COUNTER_TABLE = 1
LENGTH = None
PROTOCOL = None
SOURCE = None
DESTINATION = None
CHECK = None
FLAGS = None
COUNT = 1
HEADERLENGTH = None
SOURCE_PORT = None
DESTINATION_PORT = None
SEQ_NO = None
ACK = None
TCP_HEADER_LENGTH = None
ROWID = 0
root.grid()
root.title("Zombie Tool")

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

# ************toolbar************

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

# ****************************sniff table*********************

tv = ttk.Treeview(f2, height=6, selectmode="extended")
tv["columns"] = ('NO.', 'time', 'source', 'destination', 'protocol', 'length', 'info')
tv.heading("#0", text="NO", anchor="w")
tv.column("#0", stretch=NO, width=0, anchor="w")
tv.heading("NO.", text="NO.", anchor="w")
tv.column("NO.", stretch=YES, width=51, anchor="w")
tv.heading("time", text="Time", anchor="w")
tv.column("time", stretch=YES, width=143, anchor="w")
tv.heading("source", text="Source", anchor="w")
tv.column("source", stretch=YES, width=200, anchor="w")
tv.heading("destination", text="Destination", anchor="w")
tv.column("destination", stretch=YES, width=200, anchor="w")
tv.heading("protocol", text="Protocol", anchor="w")
tv.column("protocol", stretch=YES, width=300, anchor="w")
tv.heading("length", text="Length", anchor="w")
tv.column("length", stretch=YES, width=50, anchor="w")
tv.heading("info", text="INFO", anchor="w")
tv.column("info", stretch=YES, width=400, anchor="w")
tv.pack(side=TOP, fill=X)
tv.bind('<ButtonRelease-1>', Choose_Row_From_tv)
# ******************** Analysis Table *******************************

tv2 = ttk.Treeview(f2, height=8, selectmode="extended")
tv2["columns"] = 'info'
tv2.heading("#0", text="Field", anchor="w")
tv2.heading("info", text="Data", anchor="w")
tv2.insert('', '0', 'item12', text='TCP PACKET DETAILS')
tv2.insert('', '0', 'item0', text='IP PACKET DETAILS')
tv2.insert('item12', '0', 'item17', text='TCP Header Length')
tv2.insert('item12', '0', 'item16', text='ACK:')
tv2.insert('item12', '0', 'item15', text='SEQ Number:')
tv2.insert('item12', '0', 'item14', text='Destination Port:')
tv2.insert('item12', '0', 'item13', text='Source Port:')
tv2.insert('item0', '0', 'item11', text='CheckSum:')
tv2.insert('item0', '0', 'item10', text='Flag:')
tv2.insert('item0', '0', 'item9', text='Header Length:')
tv2.insert('item0', '0', 'item8', text='Total Length')
tv2.insert('item0', '0', 'item7', text='IP Destination:')
tv2.insert('item0', '0', 'item6', text='IP Source:')
tv2.insert('item0', '0', 'item5', text='TTL')
tv2.insert('item0', '0', 'item4', text='Fragment Offset:')
tv2.insert('item0', '0', 'item3', text='ID: ')
tv2.insert('item0', '0', 'item1', text='version: ')
tv2.pack(side=TOP, fill=X)

# ************************** database table for Analysis table *******************

tv3 = ttk.Treeview(f2, height=9, selectmode="extended")
tv3["columns"] = (
'item1', 'item2', 'item3', 'item4', 'item5', 'item6', 'item7', 'item8', 'item9', 'item10', 'item11', 'item12', 'item13',
'item14', 'item15', 'item16', 'item17', 'item18')
tv3.heading("item1", text="version", anchor="w")
tv3.column("item1", stretch=YES, width=50, anchor="w")
tv3.heading("item2", text="type of service", anchor="w")
tv3.column("item2", stretch=YES, width=50, anchor="w")
tv3.heading("item3", text="id", anchor="w")
tv3.column("item3", stretch=YES, width=50, anchor="w")
tv3.heading("item4", text="fragment offst", anchor="w")
tv3.column("item4", stretch=YES, width=50, anchor="w")
tv3.heading("item5", text="ttll", anchor="w")
tv3.column("item5", stretch=YES, width=50, anchor="w")
tv3.heading("item6", text="IP Source", anchor="w")
tv3.column("item6", stretch=YES, width=51, anchor="w")
tv3.heading("item7", text="IP Destination ", anchor="w")
tv3.column("item7", stretch=NO, width=1, anchor="w")
tv3.heading("item8", text="Total length", anchor="w")
tv3.column("item8", stretch=NO, width=1, anchor="w")
tv3.heading("item9", text="Header Length", anchor="w")
tv3.column("item9", stretch=YES, width=300, anchor="w")
tv3.heading("item10", text="Flag", anchor="w")
tv3.column("item10", stretch=YES, width=50, anchor="w")
tv3.heading("item11", text="Checksum", anchor="w")
tv3.column("item11", stretch=YES, width=50, anchor="w")
tv3.heading("item12", text="Source Port", anchor="w")
tv3.column("item12", stretch=YES, width=50, anchor="w")
tv3.heading("item13", text="Dest Port", anchor="w")
tv3.column("item13", stretch=YES, width=50, anchor="w")
tv3.heading("item14", text="SEQ NO", anchor="w")
tv3.column("item14", stretch=YES, width=50, anchor="w")
tv3.heading("item15", text="ACK", anchor="w")
tv3.column("item15", stretch=NO, width=5, anchor="w")
tv3.heading("item16", text="TCP HEADER LENGTH", anchor="w")
tv3.column("item16", stretch=NO, width=5, anchor="w")
tv3.heading("item17", text="data hexa", anchor="w")
tv3.column("item17", stretch=YES, width=50, anchor="w")

# ***********************data show table******************************

tv4 = ttk.Treeview(f2, height=15, selectmode="extended")
tv4["columns"] = 'info'
tv4.heading('#0', text="N", anchor="w")
tv4.column("#0", stretch=NO, width=0, anchor="w", )
tv4.heading('info', text="Data field", anchor="w")
tv4.column("info", stretch=YES, width=200, anchor="w")
tv4.insert('', '0', 1, text='')
tv4.bind("<1>", on_click)
tv4.pack(side=TOP, fill=X)
raise_frame(f1)
root.mainloop()
