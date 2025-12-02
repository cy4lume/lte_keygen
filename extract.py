import argparse
import asyncio
import csv
import re
from enum import unique, StrEnum, Enum
from typing import List
import tqdm

import pyshark
from smspdudecoder.codecs import GSM, UCS2

from Util import ColorPrinter, print_hex
from key import *


MCC = 1
MNC = 1

@unique
class Protocol(StrEnum):
	MAC_LTE = 'mac-lte'
	DL_DCCH = 'lte_rrc'
	NAS_EPS = 'nas-eps'
	RLC_LTE = 'rlc-lte'


def parse_hex(mac_lte, param):
	return bytes.fromhex(''.join(getattr(mac_lte, param).split(':')))


def parse_int(mac_lte, param):
	return int(getattr(mac_lte, param))


class UE:

	def __init__(self, rnti: int, credentials: List[SecurityManager]):
		self.rnti = rnti
		self.credentials = credentials
		self.keys = None

		self.printer = ColorPrinter([5, 3, 21, 2])

		self.session = SessionState(
			rand=None,
			mcc=MCC,
			mnc=MNC,
			sqn=None,
			sqn_xor_ak=None,
			nas_ul_cnt=0,
			enc_alg_id=None,
			int_alg_id=None,
		)


	def parse(self, frame):
		#if self.rnti != 61:
		#	return

		printer = self.printer

		#Funky packets:
		# 13053
		# 28286

		number = int(frame.frame_info.number)
		mac_lte = frame['mac-lte']
		fields = set(mac_lte.field_names)

		if 'gsm_a_dtap_rand' in fields:
			printer.print(number, self.rnti, "Auth Request")
			printer.skip(1)

			if self.session.rand and True:
				printer.print('Ignored!', 'Ignored!')
			else:

				#self.session.autn = parse_hex(mac_lte, 'gsm_a_dtap_autn')
				self.session.rand = parse_hex(mac_lte, 'gsm_a_dtap_rand')
				self.session.sqn_xor_ak = parse_hex(mac_lte, 'gsm_a_dtap_autn_sqn_xor_ak')

				printer.print(
				#	f'AUTN: {self.session.autn.hex()}',
					f'RAND: {''.join(self.session.rand.hex())}',
					f'sqn^Ak: {''.join(self.session.sqn_xor_ak.hex())}',
				)


		elif 'nas_eps_emm_toc' in fields:
			printer.print(number, self.rnti, "Security Mode command")
			printer.skip(1)

			self.session.enc_alg_id = EEA(parse_int(mac_lte, 'nas_eps_emm_toc'))
			self.session.int_alg_id = EIA(parse_int(mac_lte, 'nas_eps_emm_toi'))

			printer.print(
				f'cipher: {self.session.enc_alg_id.name}',
				f'integrity: {self.session.int_alg_id.name}'
			)

			printer.flush()
			self.keys = [mgr.derive_all(self.session) for mgr in self.credentials]


		elif 'nas_eps_ciphered_msg' in fields:  #Ciphered message
			printer.print(number, self.rnti, 'Ciphered')
			seq = parse_int(mac_lte, 'nas_eps_seq_no')
			printer.print(seq)

			integrity = getattr(mac_lte, 'nas_eps_msg_auth_code')
			cipher = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

			printer.print(f'integrity: {integrity}')
			printer.flush()

			for keys in self.keys:
				#if number != 12222:
				#	continue

				key = keys.k_nas_enc
				print(key.hex())
				key = key[int(len(key) / 2):]
				print(f'K NAS enc:                      {key.hex()}')

				ak = int.from_bytes(keys.ak)
				print(f'count: {seq}')
				print(f'   ak: {ak}')
				count = seq ^ ak
				print(f'COUNT: {count}')

				direction = 1

				# Set to False to enable brue search.
				for seq in [seq] if True else tqdm.tqdm(range(2 ** 32)):
					count = seq ^ ak

					for bearer in range(2 ** 5):
						try:
							decrypted_raw = liblte_security_encryption_eea2(
								key,
								count,
								bearer,
								direction,
								cipher,
								len(cipher) * 8
							)

							res = decode2(decrypted_raw)
							if res:
								print(f'bearer: {bearer}')
								#break

						#decrypted = decode2(decrypted_raw)
						#print(decrypted['mac-lte'].gsm_sms_sms_text)
						except AttributeError:
							pass
				else:
					print("Could not decrypt message\n")


		elif 'nas_eps_security_header_type' in fields:
			printer.print(number, self.rnti, 'OTHER')

			query = [
				'pdcp_lte_seq_num',
			]

			for (i, field) in enumerate(query):
				if field in fields:
					printer.print(getattr(mac_lte, field))
				else:
					printer.skip(1)

			printer.skip(5)
			printer.print([s for s in fields if 'nas_eps' in s])

		printer.flush()


	pass


def decode(info_nas: bytes, src_frame) -> bytes:
	#print_hex(raw)
	fromhex = bytes.fromhex

	pcap = bytearray()

	# File Header
	pcap += fromhex('d4 c3 b2 a1')  # Magic number
	pcap += fromhex('02 00 04 00')  # Version
	pcap += fromhex('00 00 00 00')  # 0
	pcap += fromhex('00 00 00 00')  # 0
	pcap += fromhex('FF FF 00 00')  # Snap Len
	pcap += fromhex('93 00 00 00')  # IDK

	#Frame header???
	frame = bytearray()
	frame += fromhex('01 01 03 02')  #Magic numbers?
	frame += fromhex('00 3d 03 00')  #Magic numbers?
	frame += fromhex('00 04 2a b4')  #Magic numbers?
	frame += fromhex('07 01 0a 00')  #Magic numbers?
	frame += fromhex('0f 00 01')  #Magic numbers?

	#MAC-LTE
	frame += parse_hex(src_frame['MAC-LTE'], 'dlsch_header')

	# Packet Record
	pcap += fromhex('be ef be ef')  # time
	pcap += fromhex('be ef be ef')  # time
	pcap += len(frame).to_bytes(4, "little")  # Capture Len
	pcap += len(frame).to_bytes(4, 'little')  # Capture Len

	pcap += frame

	print_hex(pcap)
	with open('temp.pcap', 'wb') as f:
		f.write(pcap)

	loop = asyncio.SelectorEventLoop()  #TODO: This does not work on windows
	asyncio.set_event_loop(loop)

	#c = pyshark.InMemCapture(eventloop=loop)
	#c.set_debug(True)
	#c.parse_packet(pcap)
	c = pyshark.FileCapture('temp.pcap', eventloop=loop)

	#print(c)
	srcframe = c.next()
	c.close()

	return srcframe


def decode2(info_nas: bytes):
	printer = ColorPrinter([10, 5])

	#print(info_nas.hex())
	result = []
	for i in range(len(info_nas) - 2):
		## ....1001 marks SMS
		#if 0b1111_1001 != info_nas[i]:
		#	continue

		## Magic?
		#if info_nas[i + 1] != 0x01:
		#	continue

		## Length of message
		#if info_nas[i+2] == (len(info_nas) - i - 3):
		#	continue

		#print(f'{i})')
		#print_hex(info_nas[i:])

		msg = info_nas[i + 29:].hex()
		patterns = ['[a-zA-Z0-9]', '[\u3131-\u314e|\u314f-\u3163|\uac00-\ud7a3]', '[ \t]']
		reg = '^(' + '|'.join(patterns) + '){3,}$'
		#reg = '.+'

		try:
			gsm = GSM.decode(msg)
			if re.search(reg, gsm):
				printer.println(f'offset: {i}', 'GSM', gsm)
				result += gsm
		except:
			pass

		try:
			ucs2 = UCS2.decode(msg)
			if re.search(reg, ucs2):
				printer.println(f'offset: {i}', 'UCS2', ucs2)
				result += ucs2
		except:
			pass

	return result


def extract(cap: pyshark.FileCapture, credentials: List[SecurityManager]):
	ues = {}

	for frame in cap:
		rnti = int(frame["MAC-LTE"].rnti)

		if rnti == 65535:
			continue

		if rnti not in ues:
			print(f"New UE: {rnti}")
			ues[rnti] = UE(rnti, credentials)

		ues[rnti].parse(frame)


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)

	if False:
		unenc = bytes.fromhex(
			'07623729013401020480000000002b040881111111110000521130713430631d4135191d5e93d5e13559bd0ecfd5eb78fd9ebebfefef383c0e03'
		)
		decode2(unenc)
		exit(0)


	#Parse input parameters
	parser = argparse.ArgumentParser(
		prog="extract"
	)
	parser.add_argument("input", help="The .pcap file to analyze")
	parser.add_argument("credentials", help="The .csv file containing imsi,k,opc")
	args = parser.parse_args()

	#Fix bug in pyshark
	loop = asyncio.SelectorEventLoop()  #TODO: This does not work on windows
	asyncio.set_event_loop(loop)

	# Load SIM credentials
	credentials = []
	with open(args.credentials, newline='') as f:
		reader = csv.reader(f)
		reader.__next__()# Skip header row

		for row in reader:
			imsi, k, opc = row
			sim = SimProfile(
				imsi=int(imsi),
				k=bytes.fromhex(k),
				opc=bytes.fromhex(opc),
				amf=b"\x00\x00",
			)
			credentials.append(SecurityManager(sim))

	print(credentials)

	# Load pcap file
	display_filter = '(_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")'
	cap = pyshark.FileCapture(args.input, eventloop=loop, display_filter=display_filter)

	extract(cap, credentials)
	cap.close()
