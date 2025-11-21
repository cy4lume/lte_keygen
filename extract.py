import argparse
import asyncio
import os.path
from enum import unique, StrEnum, Enum

import pyshark

@unique
class Protocol(StrEnum):
	MAC_LTE = 'mac-lte'
	DL_DCCH = 'lte_rrc'
	NAS_EPS = 'nas-eps'
	RLC_LTE = 'rlc-lte'

@unique
class Color(StrEnum):
	END = '\x1b[0m'
	RED = '\x1b[31m'
	GREEN = '\x1b[32m'
	YELLOW = '\x1b[33m'
	BLUE = '\x1b[34m'
	MAGENTA = '\x1b[35m'
	CYAN = '\x1b[36m'
	WHITE = '\x1b[37m'
	DEFAULT = '\x1b[39m'
colors = [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, Color.MAGENTA, Color.CYAN, Color.WHITE]

class UE:

	def __init__(self, rnti):
		self.rnti = rnti
		self.temp = []

	def parse(self, frame):
		if not self.rnti == 61:
			return

		#Funky packets:
		# 13053
		# 28286

		number = int(frame.frame_info.number)
		protocol = str(frame.frame_info.protocols).removeprefix('user_dlt:mac-lte-framed')


		if "nas-eps" in protocol or True:
			mac_lte = frame['mac-lte']

			fields = [
				'lte_rrc_dl_dcch_message_element',
				'lte_rrc_dlinformationtransfer_element',
				'pdcp_lte_seq_num',
				'gsm_a_dtap_rand',
				'gsm_a_dtap_autn',
			]

			print(number, end=' ')

			for (i, field) in enumerate(fields):
				if field in mac_lte.field_names:
					print(colors[i], getattr(mac_lte, field), end=' ')

			print(Color.DEFAULT)

#		if protocol.startswith(':mac-lte:rlc-lte'):
#			protocol = protocol.removeprefix(':mac-lte:rlc-lte')
#
#			if protocol.startswith(':pdcp-lte:lte_rrc'):
#				print(number, 'asd', protocol)
#			else:
#				print(number, 'Other')
#
#			pass


		if protocol not in self.temp:
			print(number, f'\x1b[3m{Color.CYAN}{protocol}{Color.END}')
			self.temp.append(protocol)


		#print(frame.frame_info.number, frame.frame_info.protocols)

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

		(autn, rand) = extract(cap)

		print("AUTN", "".join(autn))
		print("RAND", "".join(rand))


	except FileNotFoundError:
		print("Could not open .pcap file {args.filename}")
