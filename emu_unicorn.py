# unicorn example for da Pad4wan ;)

from __future__ import print_function
from unicorn import *
from unicorn.riscv_const import *
import sys

def get_flag(uc, a0, a1):
    a0 = uc.reg_read(UC_RISCV_REG_A0)
    a1 = uc.reg_read(UC_RISCV_REG_A1)
    m = uc.mem_read(a0, 0x100)
    s = ""
    i = 0
    while m[i] != 0 and i < 0x100:
        s += chr(m[i])
        i += 1

    m = uc.mem_read(a1, 0x100)
    s = ""
    i = 0
    while m[i] != 0 and i < 0x100:
        s += chr(m[i])
        i += 1

    return s

def hook_code(uc, address, size, user_data):
    if address == 0x28ce:
        print("-- Start emulation")

    if address == 0x28f2:
        uc.reg_write(UC_RISCV_REG_PC, 0x2902)
    
    if address == 0x2926:
        print("-- Stop emulation")
        uc.emu_stop()

    if address == 0x8f0:
        m = get_flag(uc, UC_RISCV_REG_A0, UC_RISCV_REG_A1)
        print(m)
        uc.reg_write(UC_RISCV_REG_PC, 0x994)

STACK_ADDR = 0x20024000
mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

# flash
mu.mem_map(0x0, 0x4000)
# sram
mu.mem_map(0x20000000, 16*1024)
# ramx
mu.mem_map(0x20020000, 16*1024)
# periph
mu.mem_map(0x40000000, 0x10000)

f = open("RISC-V-SecureDuo_Client_Top_Board.bin","rb")
firmware = f.read()
f.close()

mu.mem_write(0, firmware[:0x3f24])
mu.mem_write(0x20000000, firmware[0x3f24:])

mu.reg_write(UC_RISCV_REG_SP, STACK_ADDR)
mu.reg_write(UC_RISCV_REG_GP, 0x20000c00)

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(0x28ce, 0x3fff)
except UcError as e:
    print("-- Exception")
    print("err %s" %e)

