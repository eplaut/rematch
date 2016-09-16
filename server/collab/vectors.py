from collections import defaultdict


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
  @staticmethod
  def match(source, target):
    # unique_values = set(source_dict.values())
    flipped_rest = defaultdict(list)
    # TODO: could be optimized by enumerating all identity matchs together
    for target_id, target_data in target.values_list('id', 'data').iterator():
      # TODO: could be optimized by uncommenting next line as most 'target'
      # values won't be present in 'source' list
      # if v in unique_values:
      flipped_rest[target_data].append(target_id)
    for source_id, source_data in source.values_list('id', 'data').iterator():
      for target_id in flipped_rest.get(source_data, ()):
        yield (source_id, target_id)


class AssemblyHashVector(HashVector):
  id = 'assembly_hash'
  name = 'Assembly Hash'


class MnemonicHashVector(HashVector):
  id = 'mnemonic_hash'
  name = 'Mnemonic Hash'


class HistogramVector(Vector):
  @staticmethod
  def match(source, target):
    pass


class MnemonicHistogramVector(HistogramVector):
  id = 'mnemonic_hist'
  name = 'Mnemonic Histogram'


class OpcodeHistogramVector(HistogramVector):
  id = 'opcode_histogram'
  name = 'Opcode Histogram'

vector_list = [DummyVector, AssemblyHashVector, MnemonicHashVector,
               MnemonicHistogramVector, OpcodeHistogramVector]
