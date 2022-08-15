#!/usr/bin/env python3

import string
from struct import unpack

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

	def mem(self, xy, d, dp, modi, r, suf=None):
		if modi == 0: return 'nop'
		if xy == 1: dp += 4
		mem = ['*dp{n}', '*dp{n}++', '*dp{n}--', '*dp{n}##', '*dp{n}%%', '*!dp{n}##'][modi - 1].format(n=dp)
		mem += ':X' if xy == 0 else ':Y'
		if suf is None: suf = 1 if d == 0 else 4
		suf = ['XXX: suf0', 'l', 'h', 'e', 'eh', ''][suf]
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
			0x3801: 'SST1 ( Serial status register 1)',
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

	def field_suf(self, s):
		# TODO: verify suf 7 being 40 bits
		return ['XXX: suf0', 'l', 'XXX: suf2 (h?)', 'XXX: suf3 (e?)', 'XXX: suf4 (eh?)', 'XXX: suf5', 'XXX: suf6', ''][s]

	def field_xy(self, x):
		return 'XY'[x]

	def disassemble(self, blob, has_header=False):
		if has_header:
			count, hst, blob = *unpack('<HH', blob[:4]), blob[4:]
			print(f'header: {count} instructions, HST = 0x{hst:04x}')
		for i in range(0, len(blob), 4):
			self.offset = 0x200 + (i // 4)
			inst = blob[i:i+4]
			binary = ' '.join(reversed([f'{b:08b}' for b in inst]))
			dis = self.decode(unpack('<I', inst)[0])
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
	# undecrypted padding?
	padding = blob[0xb3c:0xb40]
	# TODO
	encrypted = blob[0xb40:0x15b60]
	# probably for X/Y RAM
	plaintext = blob[0xb15b60:]
