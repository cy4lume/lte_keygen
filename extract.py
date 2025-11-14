import argparse
import asyncio
import os.path

import pyshark



def extract(cap: pyshark.FileCapture):
	for frame in cap:
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

		display_filter = '_ws.col.protocol == "LTE RRC DL_DCCH/NAS-EPS"'
		cap = pyshark.FileCapture(args.filename, eventloop=loop, display_filter=display_filter)

		(autn, rand) = extract(cap)

		print("AUTN", "".join(autn))
		print("RAND", "".join(rand))


	except FileNotFoundError:
		print("Could not open .pcap file {args.filename}")
