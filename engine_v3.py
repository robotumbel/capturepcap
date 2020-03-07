import socket
import datetime
import pcapy
import csv
import sys
import dpkt
import pcap


count_tcp = 0
count_udp = 0
count_normal = 0
count_paket = 0

def main1(seconds):
    global count_paket
    # list all devices
    devices = pcapy.findalldevs()
    for i in range(len(devices)):
        print ('->', devices[i])
    print ('================================')

    dev = input("Masukkan Nama Interface yang akan digunkan : ")

    print ('Engine Runing...')

    starttime = datetime.datetime.now()
    nama_pcap = 'capture_port_scen' + str(starttime) + '.pcap'
    nama_total = starttime

    while 1:
        global count_tcp
        global count_udp
        pc = pcap.pcap(promisc=True, immediate=True, name=dev)
        pcap_file = open(nama_pcap, 'wb')
        writer = dpkt.pcap.Writer(pcap_file)
        for timestamp, packet in pc:
            currenttime = datetime.datetime.now()
            timedelta = currenttime - starttime
            writer.writepkt(packet, timestamp)
            time1 = datetime.datetime.fromtimestamp(timestamp)

            parse_packet(packet, time1, starttime)
            count_paket = +1
            print(timedelta.seconds, seconds)
            if int(timedelta.seconds) >= int(seconds):
                writer.close()
                pcap_file.close()

                print('TCP :', count_tcp)
                print('UDP :', count_udp)
                print('Proses Selesai')
                sys.exit()
            else:
                pass





def tcp_flags(flags):
    con_flags = ''

    if flags & dpkt.tcp.TH_FIN:
        con_flags = con_flags + 'F'
    if flags & dpkt.tcp.TH_SYN:
        con_flags = con_flags + 'S'
    if flags & dpkt.tcp.TH_RST:
        con_flags = con_flags + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        con_flags = con_flags + 'P'
    if flags & dpkt.tcp.TH_ACK:
        con_flags = con_flags + 'A'
    if flags & dpkt.tcp.TH_URG:
        con_flags = con_flags + 'U'
    if flags & dpkt.tcp.TH_ECE:
        con_flags = con_flags + 'E'
    if flags & dpkt.tcp.TH_CWR:
        con_flags = con_flags + 'C'
    return con_flags



# function to parse a packet
def parse_packet(packet,timestamp,nama_file):
    global count_tcp
    global count_udp

    dict_paket = {}
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data

    if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
        return
    else:

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                count_tcp = count_tcp+1
                tcp = ip.data

                dict_paket[' Time'] = timestamp.isoformat()
                #print dict_paket[' Time']
                dict_paket[' Protocol'] = 'TCP'
                dict_paket[' IP_Source'] = socket.inet_ntoa(ip.src)
                dict_paket[' IP_Dest'] = socket.inet_ntoa(ip.dst)
                dict_paket[' TTL'] = str(ip.ttl)  # time to live
                dict_paket[' Panjang_Data_Capture'] = str(eth.__len__())
                dict_paket[' Lenght_Header'] = str(ip.hl*4)
                dict_paket[' Total_Lenght'] = str(ip.len) # len
                dict_paket[' Checksum_Header'] = str(ip.sum)
                dict_paket[' Identification_Header'] = str(ip.id)
                dict_paket[' Fragment_Offset'] = str(ip.off)
                dict_paket[' P_Source'] = str(tcp.sport)  # source port
                dict_paket[' P_Dest'] = str(tcp.dport)  # destination port
                dict_paket[' Ack'] = str(tcp.seq)  # seq
                dict_paket[' Seq'] = str(tcp.ack)  # ack
                dict_paket[' Flags'] = tcp_flags(tcp.flags)
                dict_paket[' Window'] = str(tcp.win)  # window size
                dict_paket[' Urg_Pointer']=str(tcp.urp)
                dict_paket[' Checksum_Protokol'] = str(tcp.sum)
                #dict_paket[' Service'] = Service(tcp.sport,tcp.dport)

                print (dict_paket)


            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                count_udp=count_udp+1
                udp = ip.data
                dict_paket[' Time'] = timestamp
                dict_paket[' Protocol'] = 'UDP'
                dict_paket[' IP_Source'] = socket.inet_ntoa(ip.src)
                dict_paket[' IP_Dest'] = socket.inet_ntoa(ip.dst)
                dict_paket[' TTL'] = str(ip.ttl)  # time to live
                dict_paket[' Panjang_Data_Capture'] = str(eth.__len__())
                dict_paket[' Lenght_Header'] = str(ip.hl * 4)
                dict_paket[' Total_Lenght'] = str(ip.len)  # len
                dict_paket[' Checksum_Header'] = str(ip.sum)
                dict_paket[' Identification_Header'] = str(ip.id)
                dict_paket[' Fragment_Offset'] = str(ip.off)
                dict_paket[' P_Source'] = str(udp.sport)  # source port
                dict_paket[' P_Dest'] = str(udp.dport)  # destination port
                dict_paket[' Ack'] = str('')  # seq
                dict_paket[' Seq'] = str('')  # ack
                dict_paket[' Flags'] = str('')
                dict_paket[' Window'] = str('')  # window size
                dict_paket[' Urg_Pointer'] = str('')
                dict_paket[' Checksum_Protokol'] = str(udp.sum)
                #[' Service'] = Service(udp.sport, udp.dport)
                print (dict_paket)

            #if dict_paket != {}:
             #   naiv_bayes(dict_paket,nama_file)




if __name__ == "__main__":
    #waktu = datetime.datetime.now()
    print ('Welcom to Engine Detection Port Scenning')
    print ('=====================================')
    seconds = int(input("Time Run For Engine (Detik) :"))


    try:
        main1(seconds)
    except KeyboardInterrupt:
        print('Interrupt')
        print('TCP :', count_tcp)
        print('UDP :', count_udp)
        print('Proses Selesai')
        sys.exit()