from . import Vector 
from .. import exceptions
import idaapi
import ctypes

# we only do 64b-len hashes, not 32b
# TODO XXX create a native function to do this hash
class FnvHash:
  FNV_P = 0x100000001b3
  FNV_OFF_BASE = 0xcbf29ce484222325
  BITNESS = 2**64

class FnvHashVector(Vector):

  def collect(self,ea):
    fn = idaapi.get_func(ea)
    if None == fn:
      raise exceptions.NoFunctionException()
    collect_insn(fn)

  # TODO XXX multiplex.
  # Move from Byte to Dword.
  #  For every basic block 
  # calculate FNV Hash.
  # then add it to a global lst
  def collect_insn(fn):
    lst = []
    fn_lst = []
    for basicblock in fn:
      for insn in basicblock.succs():
        bb_start = insn.startEA
        bb_end = insn.endEA
        while bb_start < bb_end:
          insn_len = idaapi.decode_insn(bb_start)
          indx = 0
          while indx < insn_len:
            lst.append(Byte(start + indx))
            indx +=1
          bb_start = NextHead(bb_start)
        fn_lst.append(digest(lst))
        lst = [] 
    return fn_lst

  def digest(self,bytearr):
    h = FnvHash.FNV_OFF_BASE
    for b in bytearr:
      h = h ^ b
      h = (h * FnvHash.FNV_P) % FnvHash.BITNESS
    return h

