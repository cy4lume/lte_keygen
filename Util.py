from enum import StrEnum, unique


# https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
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


class ColorPrinter:
	colors = [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, Color.MAGENTA, Color.CYAN, Color.WHITE]

	def __init__(self, lens=[]):
		self.i = 0
		self.lens = lens + [0] * 1000

	def print(self, *msg):
		for s in msg:
			s = str(s)

			if self.i < len(self.lens):
				leng = max(self.lens[self.i], len(s))
			else:
				leng = len(s)

			if self.i > 0 and leng > 0:
				print(' ', end='')

			print(
				ColorPrinter.colors[self.i % len(ColorPrinter.colors)],
				s.ljust(leng),
				Color.DEFAULT,
				end='',
				sep=''
			)

			self.lens[self.i] = leng
			self.i += 1

	def println(self, *msg):
		for m in msg:
			self.print(m)
		self.flush()

	def skip(self, n):
		for i in range(n):
			self.print('')

	def flush(self):
		if (self.i > 0):
			self.i = 0
			print()


def print_hex(bytes):
	temp = bytes.hex(' ')
	for i in range(0, len(temp), 4 * 3):
		print(temp[i:i + 4 * 3], end='  ')
		if int(i / (4 * 3) + 1) % 4 == 0:
			print()
	print()