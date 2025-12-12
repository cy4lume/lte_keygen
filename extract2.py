import argparse
import asyncio
import csv
from io import BufferedReader, BufferedWriter
from typing import List

import pyshark

from Util import *
from key import *


MCC = 0xf001
MNC = 0xff01

log = ColorPrinter()


def parse_hex(frame, param):
	raw = str(getattr(frame, param)).removeprefix('0x')
	return Data(bytes.fromhex(''.join(raw.split(':'))))


def parse_int(frame, param):
	return int(getattr(frame, param))


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

			for old, new in replacements:
				log.print('Old:')
				log.print_hex(old)

				log.print('New:')
				log.print_hex(new)

				i = data.find(old)
				log.print(i, i + len(old))
				if i != -1:
					data[i:i + len(old)] = new

			self.oup.write(data)
		else:

			#log.print('Transfering:')
			#log.print_hex(data)

			self.oup.write(data)


	def __iter__(self):
		return self

	def __next__(self):
		frame = self.cap.next()

		if frame:

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


@dataclass(frozen=True)
class RNTI:
	type: RNTIType
	rnti: int

	def __str__(self):
		return f'{self.type.name:>2}-{self.rnti}'


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
			self.parse_security_mode_command(mac_lte)

		elif 'nas_eps_ciphered_msg' in fields:  #Ciphered message
			replacements = self.parse_ciphered(direction, mac_lte)

		elif 'nas_eps_security_header_type' in fields:
			log.skip_tab(1)
			log.print_tab('OTHER NAS-EPS')
			log.print_tab('IGNORED!')

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

			log.print(f'sqn^Ak: {''.join(self.session.sqn_xor_ak.hex())}')
			log.print(f'RAND: {''.join(self.session.rand.hex())}')
			log.print(f'AMF: {''.join(self.amf.hex())}')
			log.print(f'MAC: {''.join(self.mac.hex())}')


	def parse_security_mode_command(self, mac_lte):
		log.print_tab('Security Mode command')
		session = self.session

		session.enc_alg_id = EEA(parse_int(mac_lte, 'nas_eps_emm_toc'))
		session.int_alg_id = EIA(parse_int(mac_lte, 'nas_eps_emm_toi'))

		log.print(f'message: {session.enc_alg_id.name}')
		log.print(f'integrity: {session.int_alg_id.name}')

		for mgr in self.credentials:
			keys = mgr.derive_all(session)

			sqn = bytes(x ^ y for x, y in zip(session.sqn_xor_ak, keys.ak))
			xmac = mgr.milenage.f1(session.rand, sqn, self.amf)

			if xmac == self.mac:
				log.print('Found credentials!', color=Color.YELLOW)
				self.keys = keys

				log.print('k_asme:')
				log.print_hex(keys.k_asme)

				log.print('K NAS int:')
				log.print_hex(keys.k_nas_int)

				break

		else:
			log.print('Missing credentials!', color=Color.RED)


	def parse_ciphered(self, direction, mac_lte):
		log.print_tab("Ciphered")

		seq = parse_int(mac_lte, 'nas_eps_seq_no')
		log.print_tab(f'SEQ: {seq:x}')

		session = self.session

		mac = parse_hex(mac_lte, 'nas_eps_msg_auth_code')
		ciphered_message = parse_hex(mac_lte, 'nas_eps_ciphered_msg')

		log.print_tab(f'MAC: {mac.hex()}')
		log.flush_tab()

		log.print('Ciphered:')
		log.print_hex(ciphered_message)

		deciphered_message = None
		if session.enc_alg_id == EEA.EEA0 and session.int_alg_id == EIA.EIA0:
			deciphered_message = ciphered_message

		elif self.keys:
			key_enc = self.keys.k_nas_enc[16:]
			key_int = self.keys.k_nas_int[16:]

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
				log.print(f"TODO! implement {session.enc_alg_id.name}", color=Color.RED)
				return

			log.print('TODO: verify integrity', color=Color.RED)

		##TODO: Get this working!!!
		#if session.int_alg_id == EIA.EIA2:
		#	if liblte_security_128_eia2(
		#			key_int,
		#			seq,
		#			bearer,
		#			direction,
		#			ciphered_message,
		#			len(ciphered_message) * 8,
		#			mac
		#	):
		#		break
		#	else:
		#		deciphered_message = None
		#		print('Failed integrity check!')
		#else:
		#	print(f'TODO! implement {session.int_alg_id.name}')
		#	return
		else:
			print('Missing Auth Request!')

		if not deciphered_message:
			log.print('Could not decipher data!', color=Color.RED)
			return

		log.print('Deciphered:')
		log.print_hex(deciphered_message)

		old_pdu = parse_hex(mac_lte, 'rlc_lte_am_data')

		new_pdu = ''.join(f'{b:08b}' for b in old_pdu)

		old = ''.join(f'{b:08b}' for b in ciphered_message)
		new = ''.join(f'{b:08b}' for b in deciphered_message)
		new_pdu = new_pdu.replace(old, new)

		new_pdu = bytes([int(new_pdu[i:i + 8], 2) for i in range(0, len(new_pdu), 8)])

		return [(old_pdu, new_pdu)]


	def parse_mac_lte(self, mac_lte):
		log.print_tab("MAC-LTE")

		log.print('TODO!')



def decode(
		trans: PCapTransfer,
		credentials: List[SecurityManager],
):
	ues = {}

	for frame in trans:
		print()

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
				log.push()
				replacements = ues[rnti].parse(frame)
				log.pop()

		log.push()
		trans.transfer(replacements)
		log.pop()


if __name__ == '__main__':
	#((_ws.col.protocol != "LTE RRC DL_SCH") && !(_ws.col.protocol == "MAC-LTE")) && (mac-lte.rnti == 61)

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
	trans = PCapTransfer(
		args.input,
		args.output
	)

	try:
		decode(trans, credentials)
	finally:
		trans.close()
