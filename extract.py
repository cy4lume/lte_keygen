import argparse
import asyncio
import csv
import os.path
import sys
from enum import unique, StrEnum, Enum
from typing import List, Tuple
import tqdm

import pyshark

from Util import ColorPrinter, print_hex
from key import *


@unique
class Protocol(StrEnum):
	MAC_LTE = 'mac-lte'
	DL_DCCH = 'lte_rrc'
	NAS_EPS = 'nas-eps'
	RLC_LTE = 'rlc-lte'


class UE:

	def __init__(self, rnti: int, credentials: List[SecurityManager]):
		self.rnti = rnti
		self.credentials = credentials
		self.keys = None

		self.printer = ColorPrinter()

		self.session = SessionState(
			rand=None,
			mcc=0,
			mnc=0,
			sqn=None,
			sqn_xor_ak=None,
			nas_ul_cnt=0,
			enc_alg_id=None,
			int_alg_id=None,
		)


	def parse(self, frame):
		if self.rnti != 61:
			return

		printer = self.printer

		def parse_hex(mac_lte, param):
			return bytes.fromhex(''.join(getattr(mac_lte, param).split(':')))

		def parse_int(mac_lte, param):
			return int(getattr(mac_lte, param))

		#Funky packets:
		# 13053
		# 28286

		number = int(frame.frame_info.number)
		mac_lte = frame['mac-lte']
		fields = set(mac_lte.field_names)

		if 'gsm_a_dtap_autn' in fields:
			printer.print(number, self.rnti, "Auth Request")
			printer.skip(3)

			self.session.autn = parse_hex(mac_lte, 'gsm_a_dtap_autn')
			self.session.rand = parse_hex(mac_lte, 'gsm_a_dtap_rand')
			self.session.sqn_xor_ak = parse_hex(mac_lte, 'gsm_a_dtap_autn_sqn_xor_ak')

			printer.print(
				f'AUTN: {self.session.autn.hex()}',
				f'RAND: {''.join(self.session.rand.hex())}',
				f'sqn^Ak: {''.join(self.session.sqn_xor_ak.hex())}',
			)


		elif 'nas_eps_emm_toc' in fields:
			printer.print(number, self.rnti, "Security Mode command")
			printer.skip(3)

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

			printer.skip(4)

			integrity = getattr(mac_lte, 'nas_eps_msg_auth_code')
			cipher = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

			printer.print(f'integrity: {integrity}')
			printer.flush()

			for keys in self.keys:
				if number != 2705:
					continue

				key = keys.k_nas_enc
				print(key.hex())
				key = key[int(len(key) / 2):]
				print(f'K NAS enc:                      {key.hex()}')

				ak = int.from_bytes(keys.ak)
				print(f'count: {seq}')
				print(f'   ak: {ak}')
				count = seq ^ ak
				print(f'COUNT: {count}')

				# Set to False to enable brue search.
				for seq in [seq] if True else tqdm.tqdm(range(2 ** 32)):
					count = seq ^ ak

					for direction in range(2 ** 1):
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

								decrypted = decode(decrypted_raw)
								print(decrypted['mac-lte'].gsm_sms_sms_text)

								break
							except AttributeError:
								pass
				else:
					print("Could not decrypt message")


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


def decode(raw: bytes) -> bytes:
	#print_hex(raw)

	out = bytearray()

	# File Header
	out += bytes.fromhex('d4 c3 b2 a1')  # Magic number
	out += bytes.fromhex('02 00 04 00')  # Version
	out += bytes.fromhex('00 00 00 00')  # 0
	out += bytes.fromhex('00 00 00 00')  # 0
	out += bytes.fromhex('FF FF 00 00')  # Snap Len
	out += bytes.fromhex('93 00 00 00')  # IDK

	# Packet Record
	out += bytes.fromhex('be ef be ef')  # time
	out += bytes.fromhex('be ef be ef')  # time
	out += len(raw).to_bytes(4, "little")  # Capture Len
	out += len(raw).to_bytes(4, 'little')  # Capture Len

	out += raw

	print_hex(out)
	with open('temp.pcap', 'wb') as f:
		f.write(out)

	loop = asyncio.SelectorEventLoop()  #TODO: This does not work on windows
	asyncio.set_event_loop(loop)

	#c = pyshark.InMemCapture(eventloop=loop)
	#c.set_debug(True)
	#c.parse_packet(out)
	c = pyshark.FileCapture('temp.pcap', eventloop=loop)

	#print(c)
	frame = c.next()
	c.close()

	return frame

def extract(cap: pyshark.FileCapture, credentials: List[SecurityManager]):
	ues = {}

	frames = [frame for frame in cap]
	cap.close()

	for frame in frames:
		rnti = int(frame["MAC-LTE"].rnti)

		if rnti == 65535:
			continue

		if rnti not in ues:
			print(f"New UE: {rnti}")
			ues[rnti] = UE(rnti, credentials)

		ues[rnti].parse(frame)


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)

#	unenc = bytes.fromhex(
#		'01010302003d030000040d5407010a000f000122361fa0020308016139bd318418483b1118c809000808240000000000b820440888888888000290898389222b18368bdaca767818e84d80ef00000000'
#	)
#	decode(unenc)
#	exit(0)

	parser = argparse.ArgumentParser(
		prog="extract"
	)
	parser.add_argument("input", help="The .pcap file to analyze")
	parser.add_argument("credentials", help="The .csv file containing imsi,k,opc")
	args = parser.parse_args()

	loop = asyncio.SelectorEventLoop()  #TODO: This does not work on windows
	asyncio.set_event_loop(loop)

	credentials = []
	with open(args.credentials, newline='') as f:
		reader = csv.reader(f)
		reader.__next__()

		for row in reader:
			imsi, k, opc = row
			sim = SimProfile(
				imsi=imsi,
				k=bytes.fromhex(k),
				opc=bytes.fromhex(opc),
				amf=b"\x00\x00",
			)
			credentials.append(SecurityManager(sim))

	print(credentials)

	#display_filter = '_ws.col.protocol != "LTE RRC DL_SCH"'
	display_filter = '(_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")'
	cap = pyshark.FileCapture(args.input, eventloop=loop, display_filter=display_filter)

	extract(cap, credentials)
