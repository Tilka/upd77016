#!/usr/bin/env python3

import string, struct

class FieldFormatter(string.Formatter):
	def __init__(self, decoder):
		self.decoder = decoder

	def get_value(self, key, args, kwargs):
		if isinstance(key, int):
			return args[key]
		if '(' in key:
			return eval(key, {'mem': self.decoder.mem, 'mmio': self.decoder.mmio}, kwargs)
		fun = getattr(self.decoder, 'field_' + key, None)
		if fun is None:
			return kwargs[key]
		return fun(kwargs[key[0]])

class BaseDecoder:
	def __init__(self, bitwidth):
		self.bitwidth = bitwidth
		self.patterns = []
		self.formatter = FieldFormatter(self)
		for op, asm in self.ops.items():
			op = op.replace(' ', '')
			assert len(op) == self.bitwidth
			mask = int(''.join(['1' if i in '01' else '0' for i in op]), 2)
			bits = int(''.join([i if i == '1' else '0' for i in op]), 2)
			self.patterns.append((op, asm, mask, bits))

	def _decode_fields(self, inst, op):
		fields = {}
		for i, c in enumerate(op, 1):
			if c not in '-01':
				fields[c] = (fields.get(c, 0) << 1) | ((inst >> (self.bitwidth - i)) & 1)
		return fields

	def decode(self, value):
		assert value < 1 << self.bitwidth
		for op, fmt, mask, bits in self.patterns:
			if value & mask == bits:
				fields = self._decode_fields(value, op)
				return self.formatter.format(fmt, **fields)
		return 'TODO'

	def field_suf(self, s):
		return ['XXX', 'l', 'h', 'XXX', 'e', 'XXX', 'eh', 'ehl'][s]

	def mem(self, xy, d, dp, modi, r, suf=None):
		if modi == 0: return 'nop'
		if xy == 1: dp += 4
		mem = ['*dp{n}', '*dp{n}++', '*dp{n}--', '*dp{n}##', '*dp{n}%%', '*!dp{n}##'][modi - 1].format(n=dp)
		mem += ':X' if xy == 0 else ':Y'
		if suf is None: suf = 1 if d == 0 else 4
		suf = self.field_suf(suf)
		if d == 0:
			return f'{mem} = r{r}{suf}'
		else:
			return f'r{r}{suf} = {mem}'

	def mmio(self, addr):
		if addr < 0x3800 or addr >= 0x4000:
			return ''
		# NOTE: These are based on the uPD77210 family architecture manual.
		# No idea if they apply to the older uPD77016 family.
		info = {
			0x3801: 'SST1 (Serial status register 1)',
			0x3802: 'TSST (TDM serial status register)',
			0x3803: 'TFMT (TDM frame format register)',
			0x3804: 'TTXL (TDM transmit slot register (lower))',
			0x3805: 'TTXH (TDM transmit slot register (higher))',
			0x3806: 'TRXL (TDM receive slot register (lower))',
			0x3807: 'TRXH (TDM receive slot register (higher))',
			0x3812: 'ASST (Audio serial status register)',
			0x3820: 'HDT (Host interface data register)',
			0x3821: 'HST (Host interface status register)',
			0x383D: 'reserved MMIO',
			0x383E: 'reserved MMIO',
			0x3841: 'MSHW (Memory interface setup/hold width setting register)',
			0x3843: 'MWAIT (Memory interface wait register)',
			0x3844: 'MIDX (Direct access index register)',
			0x3850: 'PMSA0 (PMT status address register 0)',
			0x3851: 'PMS0 (PMT size register 0)',
			0x3852: 'PMC0 (PMT control register 0)',
			0x3860: 'PMSA4 (PMT status address register 4)',
			0x3861: 'PMS4 (PMT size register 4)',
			0x3862: 'PMC4 (PMT control register 4)',
			0x3864: 'PMSA5 (PMT status address register 5)',
			0x3865: 'PMS5 (PMT size register 5)',
			0x3866: 'PMC5 (PMT control register 5)',
			0x3870: 'PDT0 (Port data register 0)',
			0x3871: 'PCD0 (Port command register 0)',
			0x3872: 'PDT1 (Port data register 1)',
			0x3873: 'PCD1 (Port command register 1)',
			0x3874: 'PDT2 (Port data register 2)',
			0x3875: 'PCD2 (Port command register 2)',
			0x3876: 'PDT3 (Port data register 3)',
			0x3877: 'PCD3 (Port command register 3)',
			0x3880: 'ICR0 (Interrupt control register 0)',
			0x3881: 'ICR1 (Interrupt control register 1)',
			0x3882: 'ICR2 (Interrupt control register 2)',
			0x3883: 'ICR3 (Interrupt control register 3)',
			0x3884: 'ICR4 (Interrupt control register 4)',
			0x3885: 'ICR5 (Interrupt control register 5)',
			0x3886: 'ICR6 (Interrupt control register 6)',
			0x3887: 'ICR7 (Interrupt control register 7)',
			0x3888: 'ICR8 (Interrupt control register 8)',
			0x3889: 'ICR9 (Interrupt control register 9)',
			0x388A: 'ICR10 (Interrupt control register 10)',
			0x388B: 'ICR11 (Interrupt control register 11)',
			0x3890: 'TIR0 (Timer initialization register 0)',
			0x3892: 'TCSR0 (Timer control register 0)',
			0x3894: 'TIR1 (Timer initialization register 1)',
			0x3896: 'TCSR1 (Timer control register 1)',
			0x38B0: 'CLKC (Clock control register)',
			0x38C1: 'DPR (Data paging register)',
		}.get(addr, 'MMIO (decription missing)')
		return f'  #  {info}'

class ConditionDecoder(BaseDecoder):
	ops = {
		'0000 ttt': '', # always
		'0001 ttt': 'XXX: cond1 ', # TODO: never?
		'0010 ttt': 'if r{t} == 0 ',
		'0011 ttt': 'if r{t} != 0 ',
		'0100 ttt': 'if r{t} > 0 ',
		'0101 ttt': 'if r{t} <= 0 ',
		'0110 ttt': 'if r{t} < 0 ',
		'0111 ttt': 'if r{t} == ex ',
		'1000 ttt': 'if r{t} != ex ',
	}
	def __init__(self): super().__init__(7)

class Opcode2Decoder(BaseDecoder):
	ops = {
		'0000 000 000': 'nop',
		'0001 000 bbb': 'clr(r{b})',
		'0010 aaa bbb': 'r{b} = r{a} + 1',
		'0011 aaa bbb': 'r{b} = r{a} - 1',
		'0100 aaa bbb': 'r{b} = abs(r{a})',
		'0101 aaa bbb': 'r{b} = ~r{a}',
		'0110 aaa bbb': 'r{b} = -r{a}',
		'0111 aaa bbb': 'r{b} = clip(r{a})',
		'1000 aaa bbb': 'r{b} = round(r{a})',
		'1001 aaa bbb': 'r{b} = exp(r{a})',
		'1010 aaa bbb': 'r{b} = r{a}',
		'1011 aaa bbb': 'r{b} /= r{a}',
		'1100 aaa bbb': 'r{b} += r{a}',
		'1101 aaa bbb': 'r{b} -= r{a}',
		'1110 aaa bbb': 'r{b} XXX op2_e r{a}',
		'1111 aaa bbb': 'r{b} XXX op2_f r{a}',
	}
	def __init__(self): super().__init__(10)

class Opcode3Decoder(BaseDecoder):
	ops = {
		'aaa 0000 bbb ccc': 'r{c} = lt(r{a}, r{b})',
		'aaa 0001 bbb ccc': 'r{c} = r{a}h * r{b}h',
		'aaa 0010 bbb ccc': 'r{c} += r{a}h * r{b}h',
		'aaa 0011 bbb ccc': 'r{c} -= r{a}h * r{b}h',
		'aaa 0100 bbb ccc': 'r{c} += r{a}h * r{b}l',
		'aaa 0101 bbb ccc': 'r{c} += r{a}l * r{b}l',
		'aaa 0110 bbb ccc': 'r{c} = (r{c} >> 1) + r{a}h * r{b}h',
		'aaa 0111 bbb ccc': 'r{c} = (r{c} >> 16) + r{a}h * r{b}h',
		'aaa 1000 bbb ccc': 'r{c} = r{a} + r{b}',
		'aaa 1001 bbb ccc': 'r{c} = r{a} - r{b}',
		'aaa 1010 bbb ccc': 'r{c} = r{a} & r{b}',
		'aaa 1011 bbb ccc': 'r{c} = r{a} | r{b}',
		'aaa 1100 bbb ccc': 'r{c} = r{a} ^ r{b}',
		'aaa 1101 bbb ccc': 'r{c} = r{a} s>> r{b}',
		'aaa 1110 bbb ccc': 'r{c} = r{a} u>> r{b}',
		'aaa 1111 bbb ccc': 'r{c} = r{a} << r{b}',
	}
	def __init__(self): super().__init__(13)

class uPD77016(BaseDecoder):
	ops = {
		'0000000000000000000000000000 0000': 'nop',
		'0000000000000000000000000000 0001': 'halt',
		'0000000000000000000000000000 0010': 'lpop',
		'0000000000000000000000000000 0100': 'fint',
		'0000000000000000000000000000 1001': 'stop',
		'0001 00 -- rrrrrrrr ------------- lll': 'loop r{l}l times {r} instructions (after {reladdr})',
		'0001 01 -- rrrrrrrr 0 iiiiiiiiiiiiiii': 'loop {i} times {r} instructions (after {reladdr})',
		'0001 10 ----------------------- lll': 'repeat r{l}l times',
		'0001 11 ---------- 0 iiiiiiiiiiiiiii': 'repeat {i} times',
		'0010 01 0 ------------------ ccccccc': '{cond}ret',
		'0010 01 1 ------------------ ccccccc': '{cond}reti',
		'0010 10 j ----- ddd ---------- ccccccc': '{cond}{jump_or_call} dp{d}',
		'0010 11 j -- rrrrrrrrrrrrrrrr ccccccc': '{cond}{jump_or_call} {reladdr}',
		'0011 10 --- dddddd 0 iiiiiiiiiiiiiiii': '{dest1} = {imm16}{mmio(i)}',
		'0011 10 rrr ------ 1 iiiiiiiiiiiiiiii': 'r{r}l = {imm16}',
		'0011 11 rrr dddddd 0 --------- ccccccc': '{cond}{dest1} = r{r}l',
		'0011 11 rrr ssssss 1 --------- ccccccc': '{cond}r{r}l = {source2}',
		'0100 01 rrr sss ddd 0 iiiiiiiiiiiiiiii': '*dp{d}##{i} = r{r}{suf}',
		'0100 01 rrr sss ddd 1 iiiiiiiiiiiiiiii': 'r{r}{suf} = *dp{d}##{i}',
		'0100 10 rrr sss x -- 0 iiiiiiiiiiiiiiii': '*{imm16}:{xy} = r{r}{suf}{mmio(i)}',
		'0100 10 rrr sss x -- 1 iiiiiiiiiiiiiiii': 'r{r}{suf} = *{imm16}:{xy}{mmio(i)}',
		'0100 11 sss ttt -- de xx mmm aaa yy nnn bbb': '{mem(0, d, x, m, a, s)}; {mem(1, e, y, n, b, t)}',
		'0101 oooo aaa bbb -- iiiiiiiiiiiiiiii': 'r{b} = r{a} {op_imm} {imm16}',
		'0110 oooo ooo ooo 0000000000 0ccccccc': '{cond}{op_2}',
		'0111 oooo ooo ooo de xx mmm aaa yy nnn bbb': '{op_2}; {mem(0, d, x, m, a)}; {mem(1, e, y, n, b)}',
		'1ooo oooo ooo ooo de xx mmm aaa yy nnn bbb': '{op_3}; {mem(0, d, x, m, a)}; {mem(1, e, y, n, b)}',
	}

	def __init__(self):
		super().__init__(32)
		self.cond_decoder = ConditionDecoder()
		self.op2_decoder = Opcode2Decoder()
		self.op3_decoder = Opcode3Decoder()

	def field_cond(self, c): return self.cond_decoder.decode(c)
	def field_op_2(self, o): return self.op2_decoder.decode(o)
	def field_op_3(self, o): return self.op3_decoder.decode(o)

	def field_op_imm(self, o):
		return ['+', '-', '&', '|', '^', 's>>', 'u>>', '<<'][o - 8]

	def field_imm16(self, i):
		return f'0x{i:04x}'

	def field_dest1(self, d):
		if d < 8:  return f'dp{d}'
		if d < 16: return f'dn{d - 8}'
		if d == 16: return 'dmx'
		if d == 20: return 'dmy'
		# TODO: verify these
		return ['sr', 'eir', 'stack', 'sp', 'lc', 'lsp', 'lsr1', 'lsr2', 'lsr3', 'esr'][d - 32]
	field_source2 = field_dest1

	def field_jump_or_call(self, j):
		return ['jmp', 'call'][j]

	def field_reladdr(self, r):
		absolute = (self.offset + r) & 0xFFFF
		direction = ['-^', '-v'][absolute > self.offset]
		return f'0x{absolute:04x} {direction}'

	def field_xy(self, x):
		return 'XY'[x]

	def disassemble(self, blob, has_header=False, offset=0x200):
		if has_header:
			count, hst, blob = *struct.unpack('<HH', blob[:4]), blob[4:]
			print(f'header: {count} instructions, HST = 0x{hst:04x}')
		for i in range(0, len(blob), 4):
			self.offset = offset + (i // 4)
			inst = blob[i:i+4]
			binary = ' '.join(reversed([f'{b:08b}' for b in inst]))
			try:
				dis = self.decode(struct.unpack('<I', inst)[0])
			except:
				dis = 'EXCEPTION'
			print(f'0x{self.offset:04x}: {binary}  {dis}')
			if 'jmp' in dis or 'ret' in dis:
				print()

if __name__ == '__main__':
	from sys import argv
	blob = open(argv[1], 'rb').read()
	d = uPD77016()

	# XXX: for Wii Speak host bus dump

	# IRAM clearing program
	d.disassemble(blob[0:0x40], has_header=True)
	# bootstrap program
	d.disassemble(blob[0x40:0xb3c], has_header=True)

	x_mem = [None] * 0x10000
	y_mem = [None] * 0x10000

	for i in range(0x540b):
		target = 0x851c + i
		x_mem[target], y_mem[target] = struct.unpack_from('<HH', blob, 0xb3c + i*4)

	# parse init descriptors
	data = blob[0x15b68:]
	checksum = 0
	while True:
		addr, size, flags = struct.unpack('<HHH', data[:6])
		data = data[6:]
		space = 'XY'[flags & 1]
		init = ['host', '0'][(flags >> 1) & 1]
		info = BaseDecoder.mmio(None, addr)
		if addr >= 0x8000:
			info = '  #  PAGED'
		print(f'0x{addr:04x}:{space}[{size:4}] = {init}{info}')
		if init == 'host':
			for i in range(size):
				word = struct.unpack('<H', data[:2])[0]
				if space == 'X':
					x_mem[addr + i] = word
				else:
					y_mem[addr + i] = word
				checksum += word
				checksum &= 0xFFFF
				data = data[2:]
		if flags & 4:
			break
	checksum += struct.unpack('<H', data[:2])[0]
	checksum &= 0xFFFF
	data = data[2:]
	print('checksum:', ['failed :(', 'valid :)'][checksum == 0])
	print()
	assert len(data) == 0

	print('crypto stuff:')
	for i in range(0x84be, 0x84be + 94):
		int32 = x_mem[i] + (y_mem[i] << 16)
		offset = i - 0x8000
		mod = {
			0x04d4: 0x000000bf,
			0x04e2: 0x03f31109,
			0x04e3: 0x00930911,
			0x04e4: 0x04000000,
			0x0510: 0x01080000,
			0x0511: 0x02400011,
			0x0513: 0x02440000,
			0x051a: 0x00600000,
		}.get(offset, 0)
		if mod:
			if True:
				print('ORIGINAL:')
				dword = struct.pack('<I', int32)
				d.disassemble(dword, offset=offset)
			print('MODIFIED:')
		dword = struct.pack('<I', int32 ^ mod)
		d.disassemble(dword, offset=offset)
	for i in range(0xd927, 0xd927 + 90):
		dword = struct.pack('<HH', x_mem[i], y_mem[i])
		d.disassemble(dword, offset=i - 0x8000)

	r0, r1, r2 = 0, 0, 0
	r0 = sum(y_mem[0x3d8:0x3d8+32])
	r0 = -r0 & 0xFFFF
	r1 = ~r0 & 0xFFFF
	r0h = r0
	r0l = r1
	y_mem[0x40] = r0h
	y_mem[0x41] = r0l
	y_mem[0x66] = r0h
	y_mem[0x67] = r0l

	def signed(n):
		# I don't understand negative integers in Python lol
		return struct.unpack('h', struct.pack('H', n))[0]

	def unsigned(n):
		return n & 0xFFFF

	for i in range(0x540b):
		r5 = (y_mem[0x66] << 16) | y_mem[0x67]
		# function at 0x050a..0x051b
		r1h = y_mem[0x40]
		r1l = y_mem[0x41]
		r2h = x_mem[0x24]
		r0 = signed(r2h) * unsigned(r1l)
		r3 = r0 & 0xFFFF
		r0 = (r0 >> 16) + signed(r2h) * signed(r1h)
		r1 = r0 >> 16 # signed
		r2 = r0 & 0xFFFF
		r2 <<= 16
		r0 = r2 | r3
		r0 &= 0xFF_FFFF_FFFF
		r0 >>= 1 # unsigned
		r0 += r1
		r1 = (x_mem[0x25] << 16) | x_mem[0x26]
		r1 = r0 - r1
		if r1 > 0:
			r0 += r1
		# end of function
		y_mem[0x66] = (r0 >> 16) & 0xFFFF
		y_mem[0x67] = r0 & 0xFFFF
		r1 = (y_mem[0x851c + i] << 16) | x_mem[0x851c + i]
		r1 ^= r0
		r2 = (y_mem[0x42] << 16) | y_mem[0x43]
		r1 ^= r2
		r0 += r1
		r2 = (y_mem[0x68] << 16) | y_mem[0x69]
		r0 &= r2
		if r0 == 0:
			r0 = 1
		y_mem[0x40] = (r0 >> 16) & 0xFFFF
		y_mem[0x41] = r0 & 0xFFFF
		# function at 0x04fa..0x0509
		r6 = (r1 & 0xFF_FFFF_FFFF) >> 16 # unsigned
		r2 = r6 & 0x8000
		r0 = (y_mem[0x64] << 16) | y_mem[0x65]
		if r2 == 0:
			r2 = r6 & 0x0400
			r2 <<= 1
			r0 = r6 & 0x7000
			r2 |= r0
			r2 &= 0xFF_FFFF_FFFF
			r2 >>= 10 # unsigned
			r2 += 0x44
			r0 = (y_mem[r2 & 0xFFFF] << 16) | y_mem[(r2 & 0xFFFF) + 1]
		# end of function
		r0 &= r5
		r1 ^= r0
		x_mem[0x851c + i] = r1 & 0xFFFF
		y_mem[0x851c + i] = (r1 >> 16) & 0xFFFF

	print('decrypted:')
	#for i in range(0x851c, 0x851c + 0x540b):
	# limit garbage output for debugging
	for i in range(0x851c, 0x851c + 0x100):
		dword = struct.pack('<HH', x_mem[i], y_mem[i])
		d.disassemble(dword, offset=i - 0x8000)
