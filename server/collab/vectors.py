class Vector:
  @classmethod
  def match(cls, soure, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))


class DummyVector(Vector):
  id = 'dummy'
  name = 'Dummy'

  @classmethod
  def match(cls, soure, target):
    return []


class HashVector(Vector):
  id = 'hash'
  name = 'Hash'


class AssemblyHashVector(Vector):
  id = 'assembly_hash'
  name = 'Assembly Hash'


class MnemonicHashVector(Vector):
  id = 'mnemonic_hash'
  name = 'Mnemonic Hash'


class MnemonicHistogramVector(Vector):
  id = 'mnemonic_hist'
  name = 'Mnemonic Histogram'


class OpcodeHistogramVector(Vector):
  id = 'opcode_histogram'
  name = 'Opcode Histogram'

vector_list = [DummyVector, HashVector, AssemblyHashVector,
               MnemonicHashVector, MnemonicHistogramVector,
               OpcodeHistogramVector]
