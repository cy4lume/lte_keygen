import argparse
import asyncio
import csv
import os
import shutil
import sys
from io import BufferedReader, BufferedWriter
from typing import List, Callable
import traceback

import pyshark

from util import *
from key import *
from rlc import *


MCC = 0xf001
MNC = 0xff01

log = ColorPrinter()


def get_multiple(frame, param: str, function: Callable[[str], object]):
	# Pyshark is fucking stupid with handling multiple same-name fields.
	if isinstance(frame, pyshark.packet.layers.xml_layer.XmlLayer):

		# Different naming schema, this is neither tested nor complete
		replacements = {
			'mac_lte_': 'mac-lte.',
			'nas_eps_emm_': 'nas-eps.emm.',
			'pdcp_lte_': 'pdcp-lte.',
			'rlc_lte_am_': 'rlc-lte.am.',
			'_': '-',
		}

		temp = param
		for a, b in replacements.items():
			temp = temp.replace(a, b)

		# Retrieve, potentially, multiple values
		values = []
		for x in frame._all_fields.values():
			if x.name == temp:
				values = [k.get_default_value() for k in x.all_fields]
				break

		if len(values) == 0:
			#log.print('Failed to translate parameter name', color=Color.MAGENTA)
			pass
		elif len(values) > 1:
			log.print(temp, color=Color.MAGENTA)

			log.print('Multiple values!', color=Color.MAGENTA)
			log.print(values, color=Color.MAGENTA)
			return [function(value) for value in values]

	return function(getattr(frame, param))


def parse_hex(frame, param) -> Data | list[Data]:
	return get_multiple(frame, param, lambda raw: Data(bytes.fromhex(
		''.join(str(raw).removeprefix('0x').split(':'))
	)))


def parse_int(frame, param) -> int | list[int]:
	return get_multiple(frame, param, lambda v: int(v))


class PCapTransfer():
	def __init__(
			self,
			input: str,
			output: str
	):
		log.push('PCapTransfer init')

		self.inp: BufferedReader = open(input, 'rb')
		self.oup: BufferedWriter = open(output, 'wb')

		# --- Init Pyshark ---
		#Fix bug in pyshark
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)

		# Load pcap file
		self.cap = pyshark.FileCapture(input, eventloop=loop)
		self.frame_i_in = -1
		self.frame_i_out = 1
		self.frame_len = 0

		log.print('Transfering PCAP header', color=Color.YELLOW)
		self.move(24)

		log.pop()

	def move(self, count: int, replacements=None):
		data = self.inp.read(count)

		if replacements:
			log.print(f'Replacements: {len(replacements)}')
			log.print_hex(data)

			data = Data(data)
			replaced = [0] * (len(data) + 1)
			for i, (old, new) in enumerate(replacements):
				log.print('Old:')
				log.print_hex(old)

				log.print('New:')
				log.print_hex(new)

				j = data.find(old)
				if j != -1:
					data[j:j + len(old)] = new
					replaced[j: j + len(old)] = [i+1] * len(old)

			log.print('New data:')
			for i in range(len(data)):
				log.print(
					f'{data[i]:02x}',
					end=' ' if replaced[i] == replaced[i+1] else '|',
					color=Color.GREEN if replaced[i] else Color.END
				)
				if (i + 1) % 4 == 0:
					log.print('  ', end='')

				if (i + 1) % 16 == 0:
					log.print()

			if len(data) % 16 != 0:
				log.print()

			self.oup.write(data)
		else:

			#log.print('Transfering:')
			#log.print_hex(data)

			self.oup.write(data)


	def __iter__(self):
		return self

	def __next__(self):
		frame = self.cap.next()

		if frame:# and self.frame_i_in + 1 < 33:

			self.frame_i_in += 1
			self.frame_len = parse_int(frame, 'length')

			return frame
		else:
			raise StopIteration

	def transfer(self, replacements=None):
		log.push(f'Transferring packet {self.frame_i_in}')
		self.frame_i_out += 1

		# Packet header
		self.move(16)

		# Packet body
		self.move(self.frame_len, replacements)

		log.pop()

	def skip(self):
		log.print(f'Skipping packet {self.frame_i_in}')

		# Packet header
		self.inp.seek(16, 1)

		# Packet body
		self.inp.seek(self.frame_len, 1)

	def close(self):
		self.inp.close()
		self.oup.close()
		self.cap.close()



@unique
class RNTIType(IntEnum):
	RA = 2
	C = 3
	SI = 4


@dataclass(frozen=True)
class RNTI:
	type: RNTIType
	rnti: int

	def __str__(self):
		return f'{self.type.name:>2}-{self.rnti}'

@dataclass(slots=True)
class LCIDConfig:
	lcid: int
	eea: EEA
	key: bytes
	bearer: int
	bit_len: int
	filename: str

class UE:
	keys: DerivedKeys

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

		# lcid context -> 1(rrcenc)/3(upenc).../4/5 UPenc / 1/3/4 -> AM->12bit 5->UM->7bit
		self.lcid = {
			1: LteRlcAmReassembler(LCIDConfig(lcid=1, key="", eea=EEA.EEA0, bearer=0, bit_len=12, filename="lcid1.pcap")),
			3: LteRlcAmReassembler(LCIDConfig(lcid=3, key="", eea=EEA.EEA0, bearer=1, bit_len=12, filename="lcid3.pcap")),
			4: LteRlcAmReassembler(LCIDConfig(lcid=4, key="", eea=EEA.EEA0, bearer=6, bit_len=12, filename="lcid4.pcap")),
			5: LteRlcUm5BitReassembler(LCIDConfig(lcid=5, key="", eea=EEA.EEA0, bearer=7, bit_len=7, filename="lcid5.pcap")),
		}


	def parse(self, frame):
		number = int(frame.frame_info.number)

		mac_lte = frame['mac-lte']
		fields = set(mac_lte.field_names)

		direction = int(getattr(mac_lte, 'direction'))
		#log.print_tab('UP' if direction == 0 else 'DOWN')

		replacements = None

		if 'gsm_a_dtap_rand' in fields:
			self.parse_auth_req(mac_lte)

		elif 'nas_eps_emm_toc' in fields:
			self.parse_nas_security_mode_command(mac_lte)

		elif 'lte_rrc_securitymodecommand_element' in fields:
			replacements = self.parse_as_security_mode_command(mac_lte)

		elif 'nas_eps_ciphered_msg' in fields:  #Ciphered message
			replacements = self.parse_ciphered_nas(mac_lte, direction)

		elif 'nas_eps_security_header_type' in fields:
			log.skip_tab(1)
			log.print_tab('OTHER NAS-EPS')
			log.print_tab('IGNORED!')

		elif 'pdcp_lte_security_config' in fields:
			if self.rrc_eea and self.rrc_eea != EEA.EEA0:
				replacements = self.parse_ciphered_rrc(mac_lte, direction)

		elif 'sch_sdu' in fields and not any(['rlc' in field for field in fields]):
			self.parse_mac_lte(mac_lte)

		else:
			log.print_tab('OTHER format', Color.RED + 'TODO')

		return replacements


	def parse_auth_req(self, mac_lte):
		log.print_tab('Auth Request')

		if self.session.rand and False:
			# Ignore updated auth requests
			log.print_tab('Ignored!', 'Ignored!')
		else:

			#self.session.autn = parse_hex(mac_lte, 'gsm_a_dtap_autn')
			self.session.rand = parse_hex(mac_lte, 'gsm_a_dtap_rand')
			self.session.sqn_xor_ak = parse_hex(mac_lte, 'gsm_a_dtap_autn_sqn_xor_ak')
			self.amf = parse_hex(mac_lte, 'gsm_a_dtap_autn_amf')
			self.mac = parse_hex(mac_lte, 'gsm_a_dtap_autn_mac')

			log.flush_tab()
			log.println_tab('sqn^Ak:', f'{self.session.sqn_xor_ak.hex()}')
			log.println_tab('RAND:', f'{self.session.rand.hex()}')
			log.println_tab('AMF:', f'{self.amf.hex()}')
			log.println_tab('MAC:', f'{self.mac.hex()}')


	# TS 33 401
	def parse_nas_security_mode_command(self, mac_lte):
		log.print_tab('NAS SMC')
		session = self.session

		session.enc_alg_id = EEA(parse_int(mac_lte, 'nas_eps_emm_toc'))
		session.int_alg_id = EIA(parse_int(mac_lte, 'nas_eps_emm_toi'))

		log.flush_tab()
		log.print_tab('Ciphering:', f'{session.enc_alg_id.name}')
		log.flush_tab()
		log.print_tab('Integrity:', f'{session.int_alg_id.name}')

		for mgr in self.credentials:
			keys = mgr.derive_all(session)

			self.lcid[1].config.key = keys.k_rrc_enc
			self.lcid[3].config.key = keys.k_up_enc
			self.lcid[4].config.key = keys.k_up_enc
			self.lcid[5].config.key = keys.k_up_enc

			for i in (1, 3, 4, 5):
				self.lcid[i].config.eea = EEA.EEA2

			sqn = bytes(x ^ y for x, y in zip(session.sqn_xor_ak, keys.ak))
			xmac = mgr.milenage.f1(session.rand, sqn, self.amf)

			if xmac == self.mac:
				log.print('Found credentials!', color=Color.MAGENTA)
				self.keys = keys

				log.print('K asme:', color=Color.GREEN)
				log.print_hex(keys.k_asme)

				log.print('K NAS enc:', color=Color.GREEN)
				log.print_hex(keys.k_nas_enc)

				log.print('K NAS int:', color=Color.GREEN)
				log.print_hex(keys.k_nas_int)

				log.print('K RRC enc:', color=Color.GREEN)
				log.print_hex(keys.k_rrc_enc)

				log.print('K RRC int:', color=Color.GREEN)
				log.print_hex(keys.k_rrc_int)

				log.print('K UP enc:', color=Color.GREEN)
				log.print_hex(keys.k_up_enc)

				break

		else:
			log.print('Missing credentials!', color=Color.RED)


	# TS 33 401
	def parse_as_security_mode_command(self, mac_lte):
		log.print_tab('AS SMC')

		self.rrc_eea = EEA(parse_int(mac_lte, 'lte_rrc_cipheringalgorithm'))
		self.rrc_eia = EIA(parse_int(mac_lte, 'lte_rrc_integrityprotalgorithm'))

		log.flush_tab()
		log.println_tab('RRC EEA:', self.rrc_eea)
		log.println_tab('RRC EIA:', self.rrc_eia)

		old_pdu = parse_hex(mac_lte, 'rlc_lte_am_data')

		new_pdu = Data(old_pdu)
		# Set EEA0
		new_pdu[-6] = 0

		return [(old_pdu, new_pdu)]


	def parse_ciphered_nas(self, mac_lte, direction):
		log.print_tab("Ciphered NAS")

		seq = parse_int(mac_lte, 'nas_eps_seq_no')
		log.print_tab(f'SEQ: {seq:x}')

		mac = parse_hex(mac_lte, 'nas_eps_msg_auth_code')
		ciphered_message = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

		log.print_tab(f'MAC: {mac.hex()}')
		log.flush_tab()

		if any(isinstance(p, list) for p in [seq, mac, ciphered_message]):
			log.print('TODO! Handle multiple ciphered NAS messages')

		old_pdu = parse_hex(mac_lte, 'rlc_lte_am_data')
		if isinstance(old_pdu, list):
			for pdu in old_pdu:
				tmp = ''.join(f'{b:08b}' for b in ciphered_message)
				if tmp in ''.join(f'{b:08b}' for b in pdu):
					old_pdu = pdu
					break

		bearer = 0
		deciphered_message = decipher_nas(
			ciphered_message, mac,
			self.session.enc_alg_id,
			self.session.int_alg_id,
			self.keys,
			seq, bearer, direction,
		)

		if not deciphered_message:
			return None

		# --- Repack data ---

		# Unaligned binary data
		new_pdu = ''.join(f'{b:08b}' for b in old_pdu)

		old = ''.join(f'{b:08b}' for b in ciphered_message)
		new = ''.join(f'{b:08b}' for b in deciphered_message)
		i = new_pdu.find(old) + 0

		# --- Change security header to EEA0
		new_pdu = new_pdu[:i - 48] + '0001' + new_pdu[i - 44:]

		# --- Decipher payload
		new_pdu = new_pdu.replace(old, new)

		# Return to octets
		new_pdu = bytes([int(new_pdu[i:i + 8], 2) for i in range(0, len(new_pdu), 8)])

		return [(old_pdu, new_pdu)]


	# TS 36 323
	def parse_ciphered_rrc(self, mac_lte, direction):
		log.print_tab('Ciphered RRC')

		seq = parse_int(mac_lte, 'pdcp_lte_seq_num')
		log.println_tab(f'SEQ: {seq}')

		if 'pdcp_lte_security_config_bearer' in mac_lte.field_names:
			bearer = parse_int(mac_lte, 'pdcp_lte_security_config_bearer')
		else:
			log.print('TODO! Brute force all bearers', color=Color.RED)
			bearer = 0
		log.println_tab('Bearer:', bearer)

		old_pdu = parse_hex(mac_lte, 'rlc_lte_am_data')

		if not isinstance(seq, list):
			seq = [seq]
			old_pdu = [old_pdu]

		replacements = []
		for seq, old_pdu in zip(seq, old_pdu):
			ciphered_message = old_pdu[1:]

			deciphered_message = decipher_rrc(
				ciphered_message,
				self.rrc_eea,
				self.rrc_eia,
				self.keys,
				seq, bearer, direction,
			)

			if not deciphered_message:
				continue

			new_pdu = Data(old_pdu)
			new_pdu[1:] = deciphered_message

			replacements.append((old_pdu, new_pdu))

		return replacements


	def parse_mac_lte(self, mac_lte):
		if self.rnti != 61:
			pass
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

				if lcid not in self.lcid:
					pass
				else:
					self.lcid[lcid].process_rlc_pdu(sdu)

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


# TS 33 401
def decipher_nas(
		ciphered_message: Data,
		mac: Data,
		eea: EEA, eia: EIA,
		keys: DerivedKeys,
		seq: int, bearer: int, direction: int,
) -> Data:
	log.push()
	log.print('Ciphered:')
	log.print_hex(ciphered_message)

	# --- Cipher ---
	if eea == EEA.EEA0:
		deciphered_message = ciphered_message

	elif keys:
		key_enc = keys.k_nas_enc
		key_enc = key_enc[16:]

		if eea == EEA.EEA2:
			deciphered_message = Data(liblte_security_encryption_eea2(
				key_enc,
				seq,
				bearer,
				direction,
				ciphered_message,
				len(ciphered_message) * 8
			))

		else:
			log.print(f"TODO! implement {eea.name}", color=Color.RED)
			deciphered_message = None
	else:
		log.print('Cannot decipher. Missing Auth Request!', color=Color.RED)
		deciphered_message = None

	# --- Integrity ---
	if eia != EIA.EIA0 and keys:
		#TODO!
		log.print("TODO. Implement Integrity verification!", color=Color.RED)

	#		key_int = keys.k_nas_int
	#		key_int = key_int[16:]
	#
	#		msg = deciphered_message
	#		#msg.insert(0, seq)
	#
	#		log.print('Message:')
	#		log.print_hex(msg)
	#
	#		log.print('MAC:')
	#		log.print_hex(mac)
	#		if eia == EIA.EIA2:
	#			if not liblte_security_128_eia2(
	#					key_int,
	#					seq,
	#					bearer,
	#					direction,
	#					msg,
	#					len(msg) * 8,
	#					mac
	#			):
	#				deciphered_message = None
	#				log.print('Failed integrity check!', color=Color.RED)
	#		else:
	#			log.print(f'TODO! implement {session.int_alg_id.name}')

	else:
		log.print('Cannot verify Integrity. Missing Auth Request!', color=Color.RED)

	if not deciphered_message:
		log.print('Could not decipher data!', color=Color.RED)
	else:
		log.print('Deciphered:')
		log.print_hex(deciphered_message)

	log.pop()
	return deciphered_message


def decipher_rrc(
		ciphered_message: Data,
		eea: EEA, eia: EIA,
		keys: DerivedKeys,
		seq: int, bearer: int, direction: int,
) -> Data:
	log.push('Ciphered:')
	log.print_hex(ciphered_message)

	# --- Cipher ---
	if eea == EEA.EEA0:
		deciphered_message = ciphered_message

	elif keys:
		key_enc = keys.k_rrc_enc
		key_enc = key_enc[16:]

		if eea == EEA.EEA2:
			deciphered_message = Data(liblte_security_encryption_eea2(
				key_enc,
				seq,
				bearer,
				direction,
				ciphered_message,
				len(ciphered_message) * 8
			))

		else:
			log.print(f"TODO! implement {eea.name}", color=Color.RED)
			deciphered_message = None
	else:
		log.print('Cannot decipher. Missing Auth Request!', color=Color.RED)
		deciphered_message = None

	# --- Integrity ---

	if eia != EIA.EIA0 and keys:
		key_int = keys.k_rrc_int
		key_int = key_int[16:]

		mac = deciphered_message[-4:]
		msg = deciphered_message[:-4]
		msg.insert(0, seq)

		log.print('Message:')
		log.print_hex(msg)

		log.print('MAC:')
		log.print_hex(mac)
		if eia == EIA.EIA2:
			if not liblte_security_128_eia2(
					key_int,
					seq,
					bearer,
					direction,
					msg,
					len(msg) * 8,
					mac
			):
				deciphered_message = None
				log.print('Failed integrity check!', color=Color.RED)
		else:
			log.print(f'TODO! implement {session.int_alg_id.name}')

	else:
		log.print('Cannot verify Integrity. Missing Auth Request!', color=Color.RED)

	if not deciphered_message:
		log.print('Could not decipher data!', color=Color.RED)
	else:
		log.print('Deciphered:')
		log.print_hex(deciphered_message)

	log.pop()
	return deciphered_message


def decode(
		trans: PCapTransfer,
		credentials: List[SecurityManager],
) -> bool:
	ues = {}
	repeat = False

	for frame in trans:
		log.print()

		mac_lte = frame['MAC-LTE']
		number = int(frame.frame_info.number)

		log.print_tab(number)
		#log.print_tab(parse_int(frame, 'length'))

		if parse_int(mac_lte, 'direction') == 0:
			log.print_tab('', 'Ignoring uplink')

			trans.skip()

			continue

		log.print_tab(trans.frame_i_out)

		rnti = RNTI(
			RNTIType(int(mac_lte.rnti_type)),
			int(mac_lte.rnti)
		)
		log.print_tab(rnti)

		if rnti.type == RNTIType.SI:
			log.print_tab('', 'Ignoring System Information')

			trans.skip()

			continue

		if 'rlc_lte_sequence_analysis_ok' in mac_lte.field_names:
			if getattr(mac_lte, 'rlc_lte_sequence_analysis_ok') == 'False':
				log.print('Ignoring Duplicate frame!', color=Color.BLUE)

				trans.skip()

				continue

		replacements = None
		if rnti.type == RNTIType.C:
			if rnti not in ues:
				fields = mac_lte.field_names

				if any(['rrc' in field for field in fields]):
					if 'lte_rrc_rrcconnectionsetup_element' in fields:
						log.print_tab(f'New UE: {rnti.rnti}')
						ues[rnti] = UE(rnti.rnti, credentials)

					elif 'lte_rrc_rrcconnectionreestablishment_element' in fields:
						log.print_tab(f"New UE: {rnti.rnti}")
						ues[rnti] = UE(rnti.rnti, credentials)

						log.print(Color.RED + 'TODO ' + Color.END + 'Reestablish connection (RNTI transfer)')

					else:
						log.print(Color.RED + 'TODO ' + Color.END + 'OTHER')
						continue

			if rnti not in ues:
				log.print_tab('Unknown UE, not parsing frame!')
			else:
				try:
					log.push()
					replacements = ues[rnti].parse(frame)
				except Exception:
					print('\n')
					print(traceback.format_exc(), end='')
					log.print('Could not parse frame!', color=Color.RED)
					replacements = None
				finally:
					log.pop()

		if replacements:
			replacements = [(old, new) for old, new in replacements if old != new]

			if len(replacements) > 0:
				repeat = True

		log.push()
		trans.transfer(replacements)
		log.pop()

	log.print()
	return repeat


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)
	#tmp = open('out/log.log', 'w')
	#sys.stdout = tmp
	#tmp = open('out/log.log', 'r')
	#print(tmp.read())
	#exit(1)

	# --- Parse Input Args
	parser = argparse.ArgumentParser(
		prog="extract"
	)
	parser.add_argument("input", help="The .pcap file to decrypt")
	parser.add_argument("output", help="The output .pcap file")
	parser.add_argument("credentials", help="The .csv file containing imsi,k,opc")
	args = parser.parse_args()

	# --- Load SIM credentials ---
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

	# --- Parse PCAP file ---

	file_in = args.input
	assert args.output.count('.') == 1

	iteration = 1
	while True:
		file_out = args.output.split('.')[0] + '-' + str(iteration) + '.pcap'

		log.push(f'Start iteration {iteration}')

		trans = PCapTransfer(
			file_in,
			file_out
		)

		repeat = False
		try:
			repeat = decode(trans, credentials)
		finally:
			trans.close()

		log.print(f'Stop iteration {iteration}')
		log.pop()
		log.print('--- --- --- --- --- --- --- --- --- ---')

		if not repeat:
			log.print(f'No changes made, deleting \'{file_out}\'')
			try:
				os.remove(file_out)
			finally:
				break

		if iteration > 10:
			log.print('Iteration limit!')
			break

		file_in = file_out
		iteration += 1
