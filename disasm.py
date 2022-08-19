#!/usr/bin/env python3
import string, struct
from pathlib import Path
import array

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def bswap16(buf):
    buf = bytearray(buf)
    for i in range(0, len(buf), 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    return buf

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
        return ['XXX(suf0)', 'l', 'h', 'XXX(suf3)', 'e', 'XXX(suf5)', 'eh', 'ehl'][s]

    def mem(self, xy, d, dp, modi, r, suf=None):
        if modi == 0: return 'nop'
        if xy == 1: dp += 4
        mem = ['*dp{n}', '*dp{n}++', '*dp{n}--', '*dp{n}##', '*dp{n}%%', '*!dp{n}##', 'XXX(modi7)'][modi - 1].format(n=dp)
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
            0x3800: 'TSDT/SDT1 (TDM serial data register/serial data register 1)',
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
            0x3878: 'reserved MMIO',
            0x3879: 'reserved MMIO',
            0x387A: 'POWC (Power control register)',
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
            0x3891: 'TCR0 (Timer count register 0)',
            0x3892: 'TCSR0 (Timer control register 0)',
            0x3894: 'TIR1 (Timer initialization register 1)',
            0x3895: 'TCR1 (Timer count register 1)',
            0x3896: 'TCSR1 (Timer control register 1)',
            0x38B0: 'CLKC (Clock control register)',
            0x38B1: 'reserved MMIO',
            0x38C1: 'DPR (Data paging register)',
        }.get(addr, 'MMIO (decription missing)')
        return f'  #  {info}'

class ConditionDecoder(BaseDecoder):
    ops = {
        '0000 ttt': '', # always
        '0001 ttt': 'XXX(cond1) ', # TODO: never?
        '0010 ttt': 'if r{t} == 0 ',
        '0011 ttt': 'if r{t} != 0 ',
        '0100 ttt': 'if r{t} > 0 ',
        '0101 ttt': 'if r{t} <= 0 ',
        '0110 ttt': 'if r{t} >= 0 ',
        '0111 ttt': 'if r{t} < 0 ',
        '1000 ttt': 'if r{t} == ex ',
        '1001 ttt': 'if r{t} != ex ',
        '1010 ttt': 'if r{t} XXX(condA) ',
        '1011 ttt': 'if r{t} XXX(condB) ',
        '1100 ttt': 'if r{t} XXX(condC) ',
        '1101 ttt': 'if r{t} XXX(condD) ',
        '1110 ttt': 'if r{t} XXX(condE) ',
        '1111 ttt': 'if r{t} XXX(condF) ',
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
        '1010 aaa bbb': 'r{b} XXX(op2_A) r{a}',
        '1011 aaa bbb': 'r{b} XXX(op2_B) r{a}',
        '1100 aaa bbb': 'r{b} = r{a}',
        '1101 aaa bbb': 'r{b} /= r{a}',
        '1110 aaa bbb': 'r{b} += r{a}',
        '1111 aaa bbb': 'r{b} -= r{a}',
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
        '11111111111111111111111111111111': '(padding)',
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

    def disasm_one(self, insn, offset):
        self.offset = offset
        insn_bin = f'{insn:032b}'
        binary = ' '.join((insn_bin[i:i+8] for i in range(0, 32, 8)))
        try:
            dis = self.decode(insn)
        except:
            dis = 'EXCEPTION'
        print(f'0x{self.offset:04x}: {binary}  {dis}')
        if 'jmp' in dis or 'ret' in dis:
            print()

class Bus:
        I = 0
        X = 1
        Y = 2

class Memory:
    class Addr:
        def __init__(self, bus: Bus, offset: int):
            self.bus, self.offset = bus, offset

    def __init__(self):
        self.mem = (
            array.array('H', [0] * 0x8000 * 2),
            array.array('H', [0] * 0x8000),
            array.array('H', [0] * 0x8000)
        )
        self.dpr_write(0)

    def dump(self):
        Path('imem.bin').write_bytes(self.mem[Bus.I])
        Path('dram_x.bin').write_bytes(self.mem[Bus.X])
        Path('dram_y.bin').write_bytes(self.mem[Bus.Y])

    def _xlate(self, addr: Addr) -> Addr:
        assert addr.offset < 1 << 16
        if addr.bus in (Bus.X, Bus.Y) and addr.offset & 0x8000:
            dpr = self.dpr_read()
            assert dpr == 0x80, f'unhandled DPR {dpr:4x}'
            # data buses have striped access to instruction memory
            offset = (addr.offset & 0x7fff) * 2
            if addr.bus == Bus.Y:
                offset += 1
            return self.Addr(Bus.I, offset)

        # NOTE: _xlate is called with addr.offset being 16bit word index
        if addr.bus == Bus.I and (addr.offset >> 1) & 0x8000:
            assert False, f'no imem paging yet. addr {addr.offset:4x}'

        # remap Y periph accesses into X mem (IRL there is a hole in the
        # mapping that routes the access via X or Y to actual peripheral
        # register instead of memory)
        if addr.bus == Bus.Y and 0x3800 <= addr.offset < 0x4000:
            return self.Addr(Bus.X, addr.offset)
        return addr

    def read(self, addr: Addr) -> int:
        addr = self._xlate(addr)
        return self.mem[addr.bus][addr.offset]

    def write(self, addr: Addr, val: int):
        addr = self._xlate(addr)
        self.mem[addr.bus][addr.offset] = val

    def iread(self, addr: int) -> int:
        addr *= 2
        l = self.read(self.Addr(Bus.I, addr))
        h = self.read(self.Addr(Bus.I, addr + 1))
        return h << 16 | l

    def iwrite(self, addr: int, val: int):
        addr *= 2
        self.write(self.Addr(Bus.I, addr), val & 0xffff)
        self.write(self.Addr(Bus.I, addr + 1), val >> 16)

    def iwrite_buf(self, addr: int, buf):
        for i in range(0, len(buf), 4):
            self.iwrite(addr, int.from_bytes(buf[i:i+4], 'little'))
            addr += 1

    def dpr_read(self) -> int:
        return self.read(self.Addr(Bus.X, 0x38c1)) & 0xff

    def dpr_write(self, val: int):
        self.write(self.Addr(Bus.X, 0x38c1), val & 0xff)

    # helpers for accessing imem via xy buses
    # for assisting with crypto code, not built-in hw behavior
    def read_imem32(self, addr: int):
        assert addr & 0x8000
        h = self.read(self.Addr(Bus.Y, addr))
        l = self.read(self.Addr(Bus.X, addr))
        return h << 16 | l

    def write_imem32(self, addr: int, val: int):
        assert addr & 0x8000
        self.write(self.Addr(Bus.Y, addr), (val >> 16) & 0xffff)
        self.write(self.Addr(Bus.X, addr), (val >>  0) & 0xffff)

    def xor_imem32(self, addr: int, val: int):
        self.write_imem32(addr, self.read_imem32(addr) ^ val)
    
    def read_s32_be(self, bus: Bus, addr: int):
        r = sign_extend(self.read(self.Addr(bus, addr)), 16) << 16
        r |= self.read(self.Addr(bus, addr + 1))
        return r

if __name__ == '__main__':
    import sys
    blob = Path(sys.argv[1]).read_bytes()

    # do some doctoring to fix endianness and remove pre_fw if needed
    pre_fw = bytes.fromhex('''
        0F 00 01 04 80 00 81 38  C1 38 90 48 40 82 00 38
        41 82 08 38 02 00 10 38  02 00 18 38 00 00 04 71
        E0 3E 00 1C 21 21 A0 4C  02 30 81 38 73 38 90 48
        00 81 81 38 73 38 90 48  09 00 00 00 00 00 00 2C
        ''')
    hst = int.from_bytes(blob[2:4], 'little')
    if hst == 0x104:
        blob = bswap16(blob)
        hst = 0x401
    assert hst == 0x401, 'expected host boot header'
    if blob.startswith(pre_fw):
        blob = blob[len(pre_fw):]

    d = uPD77016()
    mem = Memory()

    # XXX: for Wii Speak host bus dump

    # IRAM clearing program
    count, hst = struct.unpack_from('<2H', pre_fw, 0)
    mem.iwrite_buf(0x200, pre_fw[4:4+count*4])
    for i in range(count):
        addr = 0x200 + i
        d.disasm_one(mem.iread(addr), addr)
    # XXX: we don't simulate it running (probably doesn't matter)

    # bootstrap program
    count, hst = struct.unpack_from('<2H', blob, 0)
    mem.iwrite_buf(0x200, blob[4:4+count*4])
    blob_pos = 4 + count * 4
    for i in range(count):
        addr = 0x200 + i
        d.disasm_one(mem.iread(addr), addr)

    # we'll be at the region the irom is called to load
    # irom_bd(dst=iram:0x51c, src=blob_pos, size=0x540b*4)
    mem.iwrite_buf(0x51c, blob[blob_pos:blob_pos+0x540b * 4])
    #buf = blob[blob_pos:blob_pos+0x540b * 4]
    #for i in range(0, len(buf), 4):
    #    mem.mem[Bus.I][0x51c*2+(i//4+0)] = struct.unpack_from('<H', buf, i)[0]
    #    mem.mem[Bus.I][0x51c*2+(i//4+1)] = struct.unpack_from('<H', buf, i + 2)[0]
    blob_pos += 0x540b * 4

    # parse init descriptors
    checksum = 0
    while True:
        desc_fmt = '<3H'
        addr, count, flags = struct.unpack_from(desc_fmt, blob, blob_pos)
        blob_pos += struct.calcsize(desc_fmt)
        bus = (Bus.X, Bus.Y)[flags & 1]
        space = 'XY'[bus == Bus.Y]
        init = ['host', '0'][(flags >> 1) & 1]
        info = BaseDecoder.mmio(None, addr)
        if addr >= 0x8000:
            info = '  #  PAGED'
        print(f'0x{addr:04x}:{space}[{count:4x}] = {init}{info}')
        for i in range(count):
            word = 0
            if init == 'host':
                word = struct.unpack_from('<H', blob, blob_pos)[0]
                blob_pos += 2
            mem.write(mem.Addr(bus, addr), word)
            addr += 1
            checksum += word
            checksum &= 0xFFFF
        if flags & 4:
            break
    # can be used to tack on additional entries without needing to parse existing ones
    print(f'checksum before {checksum:x}')
    checksum += struct.unpack_from('<H', blob, blob_pos)[0]
    blob_pos += 2
    checksum &= 0xFFFF
    print('checksum:', ['failed :(', 'valid :)'][checksum == 0])
    print()
    assert blob_pos == len(blob)

    # this magic is stored by sparse inits
    magic = mem.read(mem.Addr(Bus.X, 0x383d)) << 16 | mem.read(mem.Addr(Bus.X, 0x383e))
    assert magic == 0xaf43b59d

    # the sparse inits will have loaded more code to imem[0x4be:0x51c] and imem[0x5927:0x5981]
    # however, they get modified by decrypt_body, so defer disassembling them

    # 0x03e7
    def verify_body_checksum():
        mem.dpr_write(0x80)
        crc = 0
        verify_count = mem.read(mem.Addr(Bus.Y, 1))
        for i in range(verify_count):
            r5 = mem.read_imem32(0x8200 + i)
            if crc & (1 << 31):
                r5 ^= 0x04c11db7
            crc <<= 1
            crc ^= r5
        
        expected = mem.read(mem.Addr(Bus.Y, 3)) << 16 | mem.read(mem.Addr(Bus.Y, 2))
        crc &= 0xffffffff
        if expected == 0: return
        assert crc == expected, 'die(0x99e1)'
    
    # 0x04be
    def decrypt_body():
        mem.dpr_write(0x80)
        patch_func_04be()
        patch_func_050a()

        offset = 0x4be
        for i in range(0x5e):
            addr = offset + i
            d.disasm_one(mem.iread(addr), addr)
        
        r0 = 0
        for dp4 in range(0x3d8, 0x3d8+32):
            r0 += mem.read(mem.Addr(Bus.Y, dp4))
            mem.write(mem.Addr(Bus.Y, dp4), 0)
        r0l = -r0 & 0xffff
        r0h = ~r0l & 0x7fff
        mem.write(mem.Addr(Bus.Y, 0x40), r0h)
        mem.write(mem.Addr(Bus.Y, 0x41), r0l)
        mem.write(mem.Addr(Bus.Y, 0x66), r0h)
        mem.write(mem.Addr(Bus.Y, 0x67), r0l)

        mem.dpr_write(0x80)
        addr = 0x851c
        for i in range(0x540b):
            r5 = mem.read_s32_be(Bus.Y, 0x66)
            
            r0 = func_050a()
            mem.write(mem.Addr(Bus.Y, 0x66), (r0 >> 16) & 0xffff)
            mem.write(mem.Addr(Bus.Y, 0x67), (r0 >>  0) & 0xffff)

            r1 = mem.read_imem32(addr) # actually sign extended but doesn't matter...i think
            r1 ^= r0
            r1 ^= mem.read_s32_be(Bus.Y, 0x24)
            r0 += r1
            r0 &= mem.read_s32_be(Bus.Y, 0x68)
            if r0 == 0: r0 = 1

            mem.write(mem.Addr(Bus.Y, 0x40), (r0 >> 16) & 0xffff)
            mem.write(mem.Addr(Bus.Y, 0x41), (r0 >>  0) & 0xffff)

            r0 = func_04fa(r1)
            r0 &= r5
            r1 ^= r0
            mem.write_imem32(addr, r1)
            addr += 1

        # re-obfuscate self before ending
        patch_func_04be()
        patch_func_050a()
        mem.dpr_write(0x3f)

    # 0x04fa
    def func_04fa(r1):
        r0 = mem.read_s32_be(Bus.Y, 0x64)
        r6 = r1 >> 16
        if r6 & 0x8000:
            return r0
        addr = 0x44 + (((r6 & 0x0400) << 1 | (r6 & 0x7000)) >> 10)
        r0 = mem.read_s32_be(Bus.Y, addr)
        return r0

    # 0x050a
    def func_050a():
        r1 = mem.read_s32_be(Bus.Y, 0x40)
        r2 = sign_extend(mem.read(mem.Addr(Bus.X, 0x24)), 16) << 16
        r0 = (r2 >> 16) * (r1 & 0xffff) # TODO what's up with signedness etc for this mul
        r3 = r0 & 0xffff
        r0 = (r0 >> 16) + (r2 >> 16) * (r1 >> 16) # TODO
        r1 = sign_extend(r0, 32) >> 16
        #assert (r0 & (1 << 15)) == 0
        #r1 = r0 >> 16 # TODO signed
        r2 = r0 & 0xffff
        r2 = r2 << 16
        r0 = r2 | r3
        r0 = r0 >> 1 # unsigned
        r0 = r0 + r1
        r1 = mem.read_s32_be(Bus.Y, 0x25)
        r1 = r0 - r1
        if r1 > 0: r0 = r1
        return r0

    # 0x5941
    def patch_func_04be():
        mem.xor_imem32(0x84d4, 0x000000bf)
        mem.xor_imem32(0x84e2, 0x03f31109)
        mem.xor_imem32(0x84e3, 0x00930911)
        mem.xor_imem32(0x84e4, 0x04000000)

    # 0x5960
    def patch_func_050a():
        mem.xor_imem32(0x8510, 0x01080000)
        mem.xor_imem32(0x8511, 0x02400011)
        mem.xor_imem32(0x8513, 0x02440000)
        mem.xor_imem32(0x851a, 0x00600000)

    decrypt_body()

    offset = 0x5927
    for i in range(0x5a):
        addr = offset + i
        d.disasm_one(mem.iread(addr), addr)

    mem.dump()
    '''
    offset = 0x51c
    for i in range(0x540b):
        addr = offset + i
        d.disasm_one(mem.iread(addr), addr)
    #'''
    verify_body_checksum()
    exit()

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
    mem.write(mem.Addr(Bus.Y, 0x40), r0h)
    mem.write(mem.Addr(Bus.Y, 0x41), r0l)
    mem.write(mem.Addr(Bus.Y, 0x66), r0h)
    mem.write(mem.Addr(Bus.Y, 0x67), r0l)

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
            r0 = r1
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
