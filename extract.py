import argparse
import asyncio
import csv
import re
from enum import unique, StrEnum, Enum
from io import StringIO
from itertools import zip_longest
from typing import List
from rlc import *

import pyshark
from smspdudecoder.codecs import GSM, UCS2

from util import *
from key import *


MCC = 0xf001
MNC = 0xff01

log = ColorPrinter()


@unique
class Protocol(StrEnum):
	MAC_LTE = 'mac-lte'
	DL_DCCH = 'lte_rrc'
	NAS_EPS = 'nas-eps'
	RLC_LTE = 'rlc-lte'


@unique
class RNTIType(IntEnum):
	RA = 2
	C = 3


@dataclass(frozen=True)
class RNTI:
	type: RNTIType
	rnti: int


def parse_hex(mac_lte, param):
	raw = str(getattr(mac_lte, param)).removeprefix('0x')
	return Data(bytes.fromhex(''.join(raw.split(':'))))


def parse_int(mac_lte, param):
	return int(getattr(mac_lte, param))


class UE:

	def __init__(self, rnti: int, credentials: List[SecurityManager]):
		self.rnti = rnti
		self.credentials = credentials
		self.keys = None

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

		self.reassembler = LteRlcAmReassembler("output_manual99.pcap", )

	def parse(self, frame):
		#Funky packets:
		# 13053
		# 28286

		number = int(frame.frame_info.number)

		mac_lte = frame['mac-lte']
		fields = set(mac_lte.field_names)

		log.print_tab(number, self.rnti)
		direction = int(getattr(mac_lte, 'direction'))
		log.print_tab('UP' if direction == 0 else 'DOWN')

		if 'gsm_a_dtap_rand' in fields:
			self.parse_auth_req(mac_lte)

		elif 'nas_eps_emm_toc' in fields:
			self.parse_security_mode_command(mac_lte)

		elif 'nas_eps_ciphered_msg' in fields:  #Ciphered message
			self.parse_ciphered(direction, mac_lte)

		elif 'nas_eps_security_header_type' in fields:
			log.skip_tab(1)
			log.print_tab('OTHER NAS-EPS')
			log.print_tab('IGNORED!')

		elif 'sch_sdu' in fields and not any(['nas' in field for field in fields]):
			self.parse_mac_lte(mac_lte)

		else:
			log.skip_tab(1)
			log.print_tab(Color.RED + '[TODO]')

		log.flush_tab()

	def parse_auth_req(self, mac_lte):
		log.skip_tab(1)
		log.print_tab("Auth Request")

		if self.session.rand and False:
			# Ignore updated auth requests
			log.print_tab('Ignored!', 'Ignored!')
		else:

			#self.session.autn = parse_hex(mac_lte, 'gsm_a_dtap_autn')
			self.session.rand = parse_hex(mac_lte, 'gsm_a_dtap_rand')
			self.session.sqn_xor_ak = parse_hex(mac_lte, 'gsm_a_dtap_autn_sqn_xor_ak')

			log.print_tab(f'sqn^Ak: {''.join(self.session.sqn_xor_ak.hex())}')
			log.print_tab(f'RAND: {''.join(self.session.rand.hex())}')

	def parse_security_mode_command(self, mac_lte):
		log.skip_tab(1)
		log.print_tab("Security Mode command")

		self.session.enc_alg_id = EEA(parse_int(mac_lte, 'nas_eps_emm_toc'))
		self.session.int_alg_id = EIA(parse_int(mac_lte, 'nas_eps_emm_toi'))

		log.print_tab(
			f'message: {self.session.enc_alg_id.name}',
			f'integrity: {self.session.int_alg_id.name}'
		)

		log.flush_tab()
		self.keys = [mgr.derive_all(self.session) for mgr in self.credentials]

		for keys in self.keys:
			print('k_asme:')
			log.print_hex(keys.k_asme)

			print('K NAS int:')
			log.print_hex(keys.k_nas_int)

	def parse_ciphered(self, direction: int, mac_lte):
		seq = parse_int(mac_lte, 'nas_eps_seq_no')
		log.print_tab(seq)
		log.print_tab('Ciphered')

		session = self.session

		mac = parse_hex(mac_lte, 'nas_eps_msg_auth_code')
		ciphered_message = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

		log.print_tab(f'integrity: {mac.hex()}')
		log.flush_tab()

		print(ciphered_message.hex())

		deciphered_message = None
		if session.enc_alg_id == EEA.EEA0 and session.int_alg_id == EIA.EIA0:
			deciphered_message = ciphered_message

		elif self.keys:
			for keys in self.keys:
				key_enc = keys.k_nas_enc[16:]
				key_int = keys.k_nas_int[16:]

				bearer = 0

				if session.enc_alg_id == EEA.EEA0:
					deciphered_message = ciphered_message

				elif session.enc_alg_id == EEA.EEA2:
					deciphered_message = Data(liblte_security_encryption_eea2(
						key_enc,
						seq,
						bearer,
						direction,
						ciphered_message,
						len(ciphered_message) * 8
					))
				else:
					print(f"TODO! implement {session.enc_alg_id.name}")
					return

				print('Skipping integrity check!')
				break

				#TODO: Get this working!!!
				if session.int_alg_id == EIA.EIA2:
					if liblte_security_128_eia2(
							key_int,
							seq,
							bearer,
							direction,
							ciphered_message,
							len(ciphered_message) * 8,
							mac
					):
						break
					else:
						deciphered_message = None
						print('Failed integrity check!')
				else:
					print(f'TODO! implement {session.int_alg_id.name}')
					return

		else:
			print('Missing Auth Request!')

		if not deciphered_message:
			print('Could not decipher data!')
			return

		log.push()
		parse_L3(deciphered_message)
		log.pop()

	# See TS 36.321
	def parse_mac_lte(self, mac_lte):
		lcid = int(getattr(mac_lte, 'dlsch_lcid'), base=16)
		log.print_tab(lcid)

		log.print_tab('MAC-LTE')

		# System frame number, subframe number
		framenum = parse_int(mac_lte, 'sfn')
		subframe = parse_int(mac_lte, 'subframe')

		log.print_tab(f'Frame: {framenum}-{subframe}')
		log.print_tab(f'LCID: {lcid}')

		log.flush_tab()

		#https://stackoverflow.com/a/51522145
		headers = next(v.all_fields for v in mac_lte._all_fields.values() if v.name == 'mac-lte.sch.subheader')
		sdus = next(v.all_fields for v in mac_lte._all_fields.values() if v.name == 'mac-lte.sch.sdu')

		headers = [bytes.fromhex(v.raw_value) for v in headers]
		sdus = [bytes.fromhex(v.raw_value) for v in sdus]
		
		if True:
			s_i = 0
			for header in headers:
				lcid = header[0] & 0b00011111
				print(f'{header.hex()} ({lcid:05b}):')
				if lcid == 0b00011111:
					print('Padding!')
					continue
				elif lcid == 0b00011101:
					print('Timing Advance!')
					continue
				elif 1 <= lcid <= 16:
					print(f'Logical channel {lcid}')
					pass
				else:
					print(Color.RED + 'TODO!, unkown lcid' + Color.END)
					continue
				
				sdu = sdus[s_i]
				s_i += 1
				if lcid == 3:
					self.reassembler.process_rlc_pdu(sdu)

			"""for (header, sdu) in zip_longest(headers, sdus):
				if not sdu:
					sdu = bytes()

				lcid = header[0] & 0b00011111

				print(f'{header.hex()} ({lcid:05b}):')

				if lcid == 0b00011111:
					print('Padding!')
				elif 1 <= lcid <= 10:
					print(f'Logical channel {lcid}')
				else:
					print(Color.RED + 'TODO!, unkown lcid' + Color.END)

				print(sdu)"""


def parse_L3(L3: Data):
	#TS 24.007, 24.301

	log.print('Parsing L3 Packet:', color=Color.MAGENTA)
	log.print_hex(L3)

	security, protocol = split_byte(L3.pop(), 4)  #IDK should be 0?
	msg_type = L3.pop()

	if protocol == 0b0111:
		log.print('EPS MM')

		if msg_type == 0x62:
			log.push()
			log.print('DL NAS transport', color=Color.MAGENTA)

			length = L3.pop()
			nas_msg = L3

			assert length == len(nas_msg)

			parse_nas_message_container(nas_msg)

			log.pop()
		else:
			log.print(f'OTHER (0x{msg_type:02x})', 'Ignored!')
	else:
		log.print(f'OTHER (0x{protocol:04b})', 'Ignored!')

	log.flush_tab()

	pass


def parse_nas_message_container(nas_msg):
	#TS 24.011
	log.print_hex(nas_msg)

	_, _, protocol = split_byte(nas_msg.pop(), 1, 3, 4)

	if protocol == 0x09:
		log.print('CP-DATA')
		iei = nas_msg.pop()

		if iei == 0x01:
			log.print('RPDU')

			length = nas_msg.pop()
			rpdu = nas_msg

			assert length == len(rpdu), 'RPDU length does not match data'

			msg_type = rpdu.pop() & 0b0000_0111
			msg_ref = rpdu.pop()

			if msg_type == 0b001:
				log.push()
				log.print('RP-DATA', color=Color.MAGENTA)

				origin_address_len = rpdu.pop()
				#TODO! Read the address

				tpdu = Data(rpdu[1 + origin_address_len:])
				parse_tpdu(tpdu)
				log.pop()

			else:
				log.print_tab(f'OTHER type(0x{msg_type:03b})', 'Ignored!')

		else:
			log.print_tab(f'OTHER iei({iei:02x})', 'Ignored!')

	else:
		log.print_tab(f'OTHER protocol({protocol:02x})', 'Ignored!')

	log.flush_tab()


def parse_tpdu(tpdu: Data):
	# TS 23 040
	length = tpdu.pop()
	assert length == len(tpdu), 'TPDU length does not match data'

	msg_type = tpdu.pop() & 0b0000_0011

	if msg_type == 0:
		log.print('SMS-DELIVER')
		log.print_hex(tpdu)

		log.print()
		_ = parse_address(tpdu)
		log.print_hex(tpdu)

		protocol = tpdu.pop()
		#TODO: parse protocol byte

		coding_scheme = tpdu.pop()  # TS 23 038
		#TODO: parse coding scheme fully

		if coding_scheme & 0b1100_0000 == 0:
			if coding_scheme & 0b0010_0000 == 0:
				charset = (coding_scheme & 0b0000_1100) >> 2

				time_stamp = tpdu.pop(7)
				log.print(f'Timestamp: {time_stamp.hex(' ')}')
				#TODO: parse time stamp

				log.push()
				log.print('SMS data', color=Color.MAGENTA)
				parse_tpud(tpdu, charset)
				log.pop()
			else:
				log.print('TODO: uncompress message')

		else:
			log.print('TODO: implement coding scheme {coding_scheme:08b}')

	else:
		log.print_tab(f'OTHER ({msg_type:02b})', 'Ignored!')

	log.flush_tab()


def parse_tpud(tpud: Data, charset: int):
	message_length = tpud.pop()
	#assert data_length == len(tpud), 'TP-User-Data length does not match data'

	log.print_hex(tpud)

	log.print('SMS encoding: ', end='')
	if charset == 0:
		log.print('GSM7')
		sms = decode_GSM7(tpud, message_length)
	elif charset == 2:
		log.print('UCS2')
		sms = tpud.decode('utf_16_be')
	else:
		log.print(f'TODO: implement charset {charset:02b}')
		return

	log.print(sms)


# TODO: actually parse address
# TS 24 011
def parse_address(data: Data) -> None:
	length = data.pop()

	while True:
		if data.pop() & 0x80 != 0:
			break

	data.pop(int((length + 1) / 2))
	return None


def decode_GSM7(message: Data, length: int) -> str:
	# TS 23 038
	table = [
		'@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', 'LF', 'Ø', 'ø', 'CR', 'Å', 'å',
		'D', '_', 'F', 'G', 'L', 'W', 'P', 'Y', 'S', 'Q', 'X', '1)', 'Æ', 'æ', 'ß', 'É',
		'SP', '!', '"', '#', '¤', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
		'¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
		'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
		'¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
	]

	decompress = Data()
	byte = 0
	residue = 0
	i = 0
	while len(decompress) < length:
		byte, residue = split_byte(message.pop(), 7)


	log.print_hex(decompress)



def extract(cap: pyshark.FileCapture, credentials: List[SecurityManager]):
	ues = {}

	for frame in cap:
		mac_lte = frame['MAC-LTE']
		number = int(frame.frame_info.number)

		rnti = RNTI(
			RNTIType(int(mac_lte.rnti_type)),
			int(mac_lte.rnti)
		)

		#Ignore temporary RA-RNTI
		if rnti.type == RNTIType.RA:
			continue

		#Ignore UPLink
		if int(frame['MAC-LTE'].direction) == 0:
			continue

		if rnti not in ues:
			print(f'{number}: '.ljust(5), end='')
			fields = mac_lte.field_names

			if any(['rrc' in field for field in fields]):
				if 'lte_rrc_rrcconnectionsetup_element' in fields:
					print(f"New UE: {rnti.rnti}")
					ues[rnti] = UE(rnti.rnti, credentials)

				elif 'lte_rrc_rrcconnectionreestablishment_element' in fields:
					print(f"New UE: {rnti.rnti}")
					ues[rnti] = UE(rnti.rnti, credentials)

					print(Color.RED + 'TODO ' + Color.END + 'Reestablish connection')

				else:
					print(Color.RED + 'TODO ' + Color.END + 'OTHER')
					continue

		if rnti not in ues:
			print(f'{number}: '.ljust(5), end='')
			print('SKIP!')
			continue

		ues[rnti].parse(frame)


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)

	#Parse input parameters

	#	for i in range(8):
	#		temp = split_byte(1 << i, 3, 3)
	#
	#		for b in temp:
	#			print(f'{b:08b}', end=', ')
	#		print()
	#	exit(1)

	parser = argparse.ArgumentParser(
		prog="extract"
	)
	parser.add_argument("input", help="The .pcap file to analyze")
	parser.add_argument("credentials", help="The .csv file containing imsi,k,opc")
	args = parser.parse_args()

	#Fix bug in pyshark
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)

	# Load SIM credentials
	credentials = []
	with open(args.credentials, newline='') as f:
		reader = csv.reader(f)
		reader.__next__()  # Skip header row

		for row in reader:
			imsi, k, opc = row
			sim = SimProfile(
				imsi=int(imsi),
				k=bytes.fromhex(k),
				opc=bytes.fromhex(opc),
				amf=b"\x00\x00",
			)
			credentials.append(SecurityManager(sim))

	print('Credentials:')
	print(credentials)

	# Load pcap file
	filters = [
		'(_ws.col.protocol != "LTE RRC DL_SCH")',
	#	'&& !(_ws.col.protocol == "MAC-LTE")'
	]
	display_filter = ''.join(filters)
	cap = pyshark.FileCapture(args.input, eventloop=loop, display_filter=display_filter)

	extract(cap, credentials)
	cap.close()
