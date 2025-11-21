from enum import StrEnum, unique


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

	def __init__(self):
		self.i = 0
		self.lens = [5, 0, 30, 0] + [0] * 1000
		pass

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

	def skip(self, n):
		for i in range(n):
			self.print('')

	def flush(self):
		if (self.i > 0):
			self.i = 0
			print()
