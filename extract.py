import argparse
import asyncio
import os.path
from enum import unique, StrEnum, Enum

import pyshark

import key
from Util import ColorPrinter


@unique
class Protocol(StrEnum):
	MAC_LTE = 'mac-lte'
	DL_DCCH = 'lte_rrc'
	NAS_EPS = 'nas-eps'
	RLC_LTE = 'rlc-lte'


class UE:

	def __init__(self, rnti):
		self.rnti = rnti
		self.printer = ColorPrinter()

		self.rrc_enc = None
		self.rrc_int = None


	def parse(self, frame):
		if not self.rnti == 61:
			return

		printer = self.printer

		#Funky packets:
		# 13053
		# 28286

		number = int(frame.frame_info.number)
		mac_lte = frame['mac-lte']
		fields = set(mac_lte.field_names)


		if 'gsm_a_dtap_autn' in fields:
			printer.print(number, self.rnti, "Auth Request")
			printer.skip(3)

			autn = getattr(mac_lte, 'gsm_a_dtap_autn')
			self.autn = autn.split(':')

			rand = getattr(mac_lte, 'gsm_a_dtap_rand')
			self.rand = rand.split(':')

			printer.print(
				f'AUTN: {''.join(self.autn)}',
				f'RAND: {''.join(self.rand)}'
			)

		elif 'lte_rrc_cipheringalgorithm' in fields:
			printer.print(number, self.rnti, "Security Mode command")
			printer.skip(3)

			rrc_enc = getattr(mac_lte, 'lte_rrc_cipheringalgorithm')
			self.rrc_enc = key.EEA(int(rrc_enc))

			rrc_int = getattr(mac_lte, 'lte_rrc_integrityprotalgorithm')
			self.rrc_int = key.EIA(int(rrc_int))

			printer.print(f'cipher: {self.rrc_enc.name}', f'integrity: {self.rrc_int.name}')

		elif 'nas_eps_ciphered_msg' in fields:
			printer.print(number, self.rnti)

			querry = [
				'pdcp_lte_seq_num',
			]

			printer.print('Ciphered')

			for (i, field) in enumerate(querry):
				if field in fields:
					printer.print(getattr(mac_lte, field))
				else:
					printer.skip(1)

			printer.skip(5)
			printer.print([s for s in fields if 'nas_eps' in s])

		elif 'nas_eps_security_header_type' in fields:
			printer.print(number, self.rnti)


			querry = [
				'pdcp_lte_seq_num',
			]

			printer.print('OTHER')

			for (i, field) in enumerate(querry):
				if field in fields:
					printer.print(getattr(mac_lte, field))
				else:
					printer.skip(1)

			printer.skip(5)
			printer.print([s for s in fields if 'nas_eps' in s])

		printer.flush()


	pass

def extract(cap: pyshark.FileCapture):
	ues = {}
	for frame in cap:
		rnti = int(frame["MAC-LTE"].rnti)

		if rnti == 65535:
			continue

		if rnti not in ues:
			print(f"New UE: {rnti}")
			ues[rnti] = UE(rnti)
		ues[rnti].parse(frame)


		continue

		try:
			mac_lte = frame["MAC-LTE"]

			if "gsm_a_dtap_autn" not in mac_lte.field_names:
				continue
			if "gsm_a_dtap_rand" not in mac_lte.field_names:
				continue

			autn = mac_lte.gsm_a_dtap_autn.split(":")
			rand = mac_lte.gsm_a_dtap_rand.split(":")

			return (autn, rand)

		except Exception as e:
			print("asd", e)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		prog="extract"
	)
	parser.add_argument("filename", help="The .pcap file to analyze")
	args = parser.parse_args()


	try:
		loop = asyncio.SelectorEventLoop() #TODO: This does not work on windows
		asyncio.set_event_loop(loop)

		display_filter = '_ws.col.protocol != "LTE RRC DL_SCH"'
		cap = pyshark.FileCapture(args.filename, eventloop=loop, display_filter=display_filter)

		extract(cap)


	except FileNotFoundError:
		print("Could not open .pcap file {args.filename}")
