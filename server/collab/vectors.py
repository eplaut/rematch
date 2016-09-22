import numpy as np
import scipy as sp

from collections import defaultdict

from sklearn.preprocessing import normalize


class Vector:
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))


class DummyVector(Vector):
  match_type = 'dummy'
  name = 'Dummy'

  @classmethod
  def match(cls, soure, target):
    return []


class HashVector(Vector):
  @classmethod
  def match(cls, source, target):
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
        yield source_id, target_id, 100


class AssemblyHashVector(HashVector):
  vector_type = 'assembly_hash'
  match_type = 'assembly_hash'
  name = 'Assembly Hash'


class MnemonicHashVector(HashVector):
  vector_type = 'mnemonic_hash'
  match_type = 'mnemonic_hash'
  name = 'Mnemonic Hash'


class HistogramVector(Vector):
  @staticmethod
  def match(source, target):
    source_id, source_data = source.values('id', 'data')
    target_id, target_data = target.values('id', 'data')
    source_matrix = normalize(np.narray(source_data), axis=1, norm='l1')
    target_matrix = normalize(np.narray(target_data), axis=1, norm='l1')
    distances = sp.spatial.distance.cdist(source_matrix, target_matrix)
    for source_i in range(source_matrix.shape[0]):
      for target_i in range(target_matrix.shape[0]):
        source_id = source_id[source_i]
        target_id = target_id[target_i]
        score = distances[source_i][target_i]
        yield source_id, target_id, score


class MnemonicHistogramVector(HistogramVector):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_hist'
  name = 'Mnemonic Histogram'


class OpcodeHistogramVector(HistogramVector):
  vector_type = 'opcode_histogram'
  match_type = 'opcode_histogram'
  name = 'Opcode Histogram'

vector_list = [DummyVector, AssemblyHashVector, MnemonicHashVector,
               MnemonicHistogramVector, OpcodeHistogramVector]
