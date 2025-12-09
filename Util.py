import sys
from enum import StrEnum, unique
from itertools import count


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
		self.stack = []
		self.depth = 0

	@property
	def _prefix(self):
		if self.depth > 0:
			return '| ' * self.depth
		else:
			return ''

	def print(self, *msg, end='\n', color=None):
		if self.i != 0:
			self.flush_tab()

		print(self._prefix, end='')

		if color:
			print(color, end='')

		print(*msg, end=end)

		print(Color.END, end='')

	def print_hex(self, msg):
		temp = msg.hex()

		for i in range(len(temp)):
			if i % 32 == 0:
				print(self._prefix, end='')

			print(temp[i], end='')

			if (i + 1) % 2 == 0:
				print(' ', end='')

			if (i + 1) % 8 == 0:
				print('  ', end='')

			if (i + 1) % 32 == 0:
				print('\n', end='')

		if len(msg) % 16 != 0:
			print()

	def print_tab(self, *msg):
		for s in msg:
			s = str(s)

			if self.i < len(self.lens):
				leng = max(self.lens[self.i], len(s))
			else:
				leng = len(s)

			if self.i == 0:
				print(self._prefix, end='')

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

	def skip_tab(self, n):
		for i in range(n):
			self.print_tab('')

	def flush_tab(self):
		if (self.i > 0):
			self.i = 0
			print()

	def push(self):
		self.depth += 1
		self.stack.append((self.lens, self.i))
		self.lens = [0] * 1000
		self.i = 0

	def pop(self):
		self.depth -= 1
		self.lens, self.i = self.stack.pop()


class Data(bytearray):
	def pop(self, count=1):
		if count == 1:
			return super().pop(0)
		elif count > 1:
			slice = self[:count]
			del self[:count]
			return slice
		else:
			raise IndexError('Can not remove 0 or fewer elements')


def split_byte(byte: int, *lengths) -> list[int]:
	"""
	Splits byte into multiple parts.
	lengths: amount of bits for a given part.
	split_byte(obXXXY_YYZZ, [3, 3]) = [0bXXX, 0bYYY, 0bZZ)
	"""
	out = []

	mask = 0xff
	off = 8
	for leng in lengths:
		mask &= (mask >> leng)
		off -= leng

		#print(f'  {mask:08b}, {byte:08b} | {byte & ~mask:08b}')

		out.append((byte & ~mask) >> off)
		byte &= mask

	if mask != 0:
		out.append(byte)

	return out


def first_last_string(msg, leng, sep=' ... '):
	if len(msg) <= leng:
		return msg
	else:
		l = int((leng - len(sep)) / 2)
		r = len(msg) - l

		return msg[:l] + sep + msg[r:]
