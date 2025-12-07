import argparse
import asyncio
import csv
import re
from enum import unique, StrEnum, Enum
from io import StringIO
from itertools import zip_longest
from typing import List
import tqdm

import pyshark
from smspdudecoder.codecs import GSM, UCS2
from smspdudecoder.fields import SMSDeliver

from Util import ColorPrinter, print_hex, Color, first_last_string
from key import *


MCC = 0xf001
MNC = 0xff01


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
	return bytes.fromhex(''.join(getattr(mac_lte, param).split(':')))


def parse_int(mac_lte, param):
	return int(getattr(mac_lte, param))


class UE:

	def __init__(self, rnti: int, credentials: List[SecurityManager]):
		self.rnti = rnti
		self.credentials = credentials
		self.keys = None

		self.printer = ColorPrinter([5, 3, 4, 2, 21, 2])

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

		printer.print(number, self.rnti)
		direction = int(getattr(mac_lte, 'direction'))
		printer.print('UP' if direction == 0 else 'DOWN')

		if 'gsm_a_dtap_rand' in fields:
			self.parse_auth_req(mac_lte)

		elif 'nas_eps_emm_toc' in fields:
			self.parse_security_mode_command(mac_lte)

		elif 'nas_eps_ciphered_msg' in fields:  #Ciphered message
			self.parse_ciphered(direction, mac_lte)

		elif 'nas_eps_security_header_type' in fields:
			printer.skip(1)
			printer.print('OTHER NAS-EPS')
			printer.print('IGNORED!')

		#			query = [
		#				'pdcp_lte_seq_num',
		#			]
		#
		#			for (i, field) in enumerate(query):
		#				if field in fields:
		#					printer.print(getattr(mac_lte, field))
		#				else:
		#					printer.skip(1)
		#
		#			printer.skip(5)
		#			printer.print([s for s in fields if 'nas_eps' in s])

		elif 'sch_sdu' in fields and not any(['rlc' in field for field in fields]):
			self.parse_mac_lte(mac_lte)

		else:
			printer.skip(1)
			printer.print(Color.RED + '[TODO]')

		printer.flush()

	def parse_auth_req(self, mac_lte):
		printer = self.printer

		printer.skip(1)
		printer.print("Auth Request")

		if self.session.rand and False:
			# Ignore updated auth requests
			printer.print('Ignored!', 'Ignored!')
		else:

			#self.session.autn = parse_hex(mac_lte, 'gsm_a_dtap_autn')
			self.session.rand = parse_hex(mac_lte, 'gsm_a_dtap_rand')
			self.session.sqn_xor_ak = parse_hex(mac_lte, 'gsm_a_dtap_autn_sqn_xor_ak')

			printer.print(f'sqn^Ak: {''.join(self.session.sqn_xor_ak.hex())}')
			printer.print(f'RAND: {''.join(self.session.rand.hex())}')

	def parse_security_mode_command(self, mac_lte):
		printer = self.printer

		printer.skip(1)
		printer.print("Security Mode command")

		self.session.enc_alg_id = EEA(parse_int(mac_lte, 'nas_eps_emm_toc'))
		self.session.int_alg_id = EIA(parse_int(mac_lte, 'nas_eps_emm_toi'))

		printer.print(
			f'message: {self.session.enc_alg_id.name}',
			f'integrity: {self.session.int_alg_id.name}'
		)

		printer.flush()
		self.keys = [mgr.derive_all(self.session) for mgr in self.credentials]

		for keys in self.keys:
			print('k_asme:')
			print_hex(keys.k_asme)

			print('K NAS int:')
			print_hex(keys.k_nas_int)

	def parse_ciphered(self, direction: int, mac_lte):
		printer = self.printer

		seq = parse_int(mac_lte, 'nas_eps_seq_no')
		printer.print(seq)
		printer.print('Ciphered')

		session = self.session

		nas_mac = int(getattr(mac_lte, 'nas_eps_msg_auth_code'), base=16)
		message = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

		printer.print(f'integrity: {nas_mac:x}')
		printer.flush()

		print(message.hex())

		for keys in self.keys:
			key = keys.k_nas_enc
			key = key[int(len(key) / 2):]

			bearer = 0

			try:
				if session.enc_alg_id == EEA.EEA0:
					deciphered_raw = message
				elif session.enc_alg_id == EEA.EEA2:
					deciphered_raw = liblte_security_encryption_eea2(
						key,
						seq,
						bearer,
						direction,
						message,
						len(message) * 8
					)
				else:
					print(f"TODO! implement {session.enc_alg_id.name}")
					raise None

				if not check_integrity(session.int_alg_id, deciphered_raw, nas_mac):
					print('Failed integrity test!')
			#	continue

			#print('Deciphered:')
			#print_hex(deciphered_raw)

			#decode2(deciphered_raw)

			except:
				pass

	# See TS 36.321
	def parse_mac_lte(self, mac_lte):
		printer = self.printer

		lcid = int(getattr(mac_lte, 'dlsch_lcid'), base=16)
		printer.print(lcid)

		printer.print('MAC-LTE')

		# System frame number, subframe number
		framenum = parse_int(mac_lte, 'sfn')
		subframe = parse_int(mac_lte, 'subframe')

		printer.print(f'Frame: {framenum}-{subframe}')
		printer.print(f'LCID: {lcid}')

		printer.flush()

		#https://stackoverflow.com/a/51522145
		headers = next(v.all_fields for v in mac_lte._all_fields.values() if v.name == 'mac-lte.sch.subheader')
		sdus = next(v.all_fields for v in mac_lte._all_fields.values() if v.name == 'mac-lte.sch.sdu')

		headers = [bytes.fromhex(v.raw_value) for v in headers]
		sdus = [bytes.fromhex(v.raw_value) for v in sdus]


		if framenum == 144:
			for (header, sdu) in zip_longest(headers, sdus):
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

				print()

def check_integrity(algorithm: EIA, message: bytes, integrity: int) -> bool:
	if algorithm == EIA.EIA0:
		raise 'TODO'

	elif algorithm == EIA.EIA1:
		raise 'TODO'

	elif algorithm == EIA.EIA2:
		#TODO
		return False

	else:
		raise 'TODO'


def decode2(info_nas: bytes):
	printer = ColorPrinter([0, 10, 5])
	printer.skip(1)

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

		msg = info_nas[i + 0:].hex()
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

		try:
			sms = SMSDeliver.decode(StringIO(msg))
			printer.println(f'offset: {i}', 'SMSDeliver', sms)
		#if re.search(reg, ucs2):
		#	printer.println(f'offset: {i}', 'UCS2', ucs2)
		#	result += ucs2
		except:
			pass

	return result


def extract(cap: pyshark.FileCapture, credentials: List[SecurityManager]):
	ues = {}

	for frame in cap:
		mac_lte = frame['MAC-LTE']
		number = int(frame.frame_info.number)

		if number > 400:
			break

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
					print(Color.RED + 'TODO ' + Color.END + 'Other')
					continue

		if rnti not in ues:
			print(f'{number}: '.ljust(5), end='')
			print('SKIP!')
			continue

		ues[rnti].parse(frame)


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)

	if False:
		unenc = bytes.fromhex(
			'040881111111110000521130713430631d4135191d5e93d5e13559bd0ecfd5eb78fd9ebebfefef383c0e03'
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
	loop = asyncio.new_event_loop()
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
	filters = [
		'(_ws.col.protocol != "LTE RRC DL_SCH")',
		#		'&& !(_ws.col.protocol == "MAC-LTE")'
	]
	display_filter = ''.join(filters)
	cap = pyshark.FileCapture(args.input, eventloop=loop, display_filter=display_filter)

	extract(cap, credentials)
	cap.close()
