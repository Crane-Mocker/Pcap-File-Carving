import pyshark
from scapy.all import rdpcap

"""
Carve: raw data of MPEG-2,4 ACC
From: BLE A2DP RTP traffic

RFC: RTP Payload Format for MPEG-2 and MPEG-4 AAC Streams
https://www.ietf.org/proceedings/50/I-D/avt-rtp-mpeg2aac-01.txt

Please use Audacity>File>import> Raw Data to open the raw data

Warning: assuming there is only one stream
"""

input_file = "chall.pcapng"#put your pcap file path here
output_file = "chall.rtp"#put your output file path here

"""
pyshark

RTP layer: e.g. packet["RTP"].seq
['setup', 'setup_frame', 'setup_method', 'version', 'padding', 'ext', 
'cc', 'marker', 'p_type', 'seq', 'extseq', 'timestamp', 'ssrc'

DATA: e.g. packet["DATA"].data
['data'(hex), 'data_data'(hex:hex), 'data_len']
"""
def pkt_layers(packet):
	print("layers: ", packet.layers)

def pkt_fields(packet, layer):
	print(packet[layer].field_names)

# get the index of rtp packets
def pkt_rtp(packets):
	rtp_index = []
	for i, packet in enumerate(packets):
		if "RTP" in packet:
			rtp_index.append(i)
	return rtp_index


packets_tmp = pyshark.FileCapture(input_file)
rtp_index = pkt_rtp(packets_tmp)
#print(rtp_index)
"""
RTP layer: e.g. packets[4120].layers()
[<class 'scapy.layers.bluetooth.HCI_PHDR_Hdr'>, <class 'scapy.layers.bluetooth.HCI_Hdr'>, 
<class 'scapy.layers.bluetooth.HCI_ACL_Hdr'>, <class 'scapy.layers.bluetooth.L2CAP_Hdr'>,
<class 'scapy.packet.Raw'>]

RTP data: packets[4120]["Raw"].load <class 'bytes'>
"""

packets = rdpcap(input_file)
with open(output_file, 'wb') as output:
	for i, index in enumerate(rtp_index):
		if i == 0: #first pkt
			output.write(packets[index]["Raw"].load)
		else:
			#drop the 1st byte of RTP
			output.write(packets[index]["Raw"].load[1:])
