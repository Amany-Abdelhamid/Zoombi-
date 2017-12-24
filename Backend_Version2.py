from socket import *
import struct
import sys
import re
from datetime import datetime

# receive a datagram
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print ("An error happened: ")
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

    #get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
    #get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
    #get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
    #get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
    #the 7th bit is empty and shouldn't be analyzed

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
            reliability[R] + tabs + cost[M]
    return TOS

# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
    #get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
    #get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
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

#sniff --> parsing data received    
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
    
    unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])

    version_IHL = unpackedData[0]
    version = version_IHL >> 4                  # version of the IP
    IHL = version_IHL & 0xF                     # internet header length
    Iph_l = IHL *4                              #ip header length
    TOS = unpackedData[1]                       # type of service
    totalLength = unpackedData[2]
    ID = unpackedData[3]                        # identification
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]                       # time to live
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = inet_ntoa(unpackedData[8])
    destinationAddress = inet_ntoa(unpackedData[9])

    print ("IP Protocol Information : \n")
    print ("Version:\t\t" + str(version))
    print ("Header Length:\t\t" + str(IHL*4) + " bytes")
    print ("Type of Service:\t" + getTOS(TOS))
    print ("Length:\t\t\t" + str(totalLength))
    print ("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
    print ("Flags:\t\t\t" + getFlags(flags))
    print ("Fragment offset:\t" + str(fragmentOffset))
    print ("TTL:\t\t\t" + str(TTL))
    print ("Protocol:\t\t" + getProtocol(protocolNr))
    print ("Checksum:\t\t" + str(checksum))
    print ("Source:\t\t\t" + sourceAddress)
    print ("Destination:\t\t" + destinationAddress)
    print('Time : '+ str(datetime.now().hour)+ ":"+str(datetime.now().minute)+":"+str(datetime.now().second))
    print (" ")
    
     
    #TCP protocol
    if protocolNr == 6 :
        tcp_header = data[20:40]

        #now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
         
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        

        print ("TCP Protocol Information: ")
        print (" ")
        print ('Source Port : ' + str(source_port))
        print ('Dest Port : ' + str(dest_port))
        print ('Sequence Number : ' + str(sequence))
        print ('Acknowledgement : ' + str(acknowledgement))
        print ('TCP header length : ' + str(tcph_length))
        print(" ")
         
    #getting the data from the packet
    unpacked =''
    DATA=''
    for i in range(int(len(data)/16)):
        unpackedr =struct.unpack('!BBBBBBBBBBBBBBBB',data[i*16:(i*16)+16])
        for j in range(16):
            unpacked=unpacked+'{:02x}'.format(unpackedr[j])
            if int(unpackedr[j]) > 31 and int(unpackedr[j]) < 127:
                DATA += str(chr(int(unpackedr[j])))
            else:
                DATA += '.'
    
    index = 0
    i=0
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
        Data =Data[:-1] +"   " +DATA[i:i+16]+'\n'
        i += 16

   
    print ('Data : \n' + str(Data))
    print(" ")
    
    # disabled promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)
        
   
for k in range(3):
    sniff()
