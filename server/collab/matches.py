import numpy as np
import scipy as sp

import collections
import itertools

from sklearn.preprocessing import normalize


class Match:
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))


class HashMatch(Match):
  @classmethod
  def match(cls, source, target):
    # unique_values = set(source_dict.values())
    flipped_rest = collections.defaultdict(list)
    # TODO: could be optimized by enumerating all identity matchs together
    target_values = target.values_list('id', 'instance_id', 'data').iterator()
    for target_id, target_instance_id, target_data in target_values:
      # TODO: could be optimized by uncommenting next line as most 'target'
      # values won't be present in 'source' list
      # if v in unique_values:
      flipped_rest[target_data].append(target_id, target_instance_id)
    source_values = source.values_list('id', 'instance_id', 'data').iterator()
    for source_id, source_instance_id, source_data in source_values:
      for target_id, target_instance_id in flipped_rest.get(source_data, ()):
        yield source_id, source_instance_id, target_id, target_instance_id, 100


class AssemblyHashMatch(HashMatch):
  vector_type = 'assembly_hash'
  match_type = 'assembly_hash'


class MnemonicHashMatch(HashMatch):
  vector_type = 'mnemonic_hash'
  match_type = 'mnemonic_hash'


class HistogramMatch(Match):
  @staticmethod
  def match(source, target):
    source_values = itertools.izip(*source.values('id', 'instance_id', 'data'))
    target_values = itertools.izip(*target.values('id', 'instance_id', 'data'))

    if not source_values or not target_values:
      return
    source_id, source_instance_id, source_data = source_values
    target_id, target_instance_id, target_data = target_values
    source_matrix = normalize(np.narray(source_data), axis=1, norm='l1')
    target_matrix = normalize(np.narray(target_data), axis=1, norm='l1')
    distances = sp.spatial.distance.cdist(source_matrix, target_matrix)
    for source_i in range(source_matrix.shape[0]):
      for target_i in range(target_matrix.shape[0]):
        source_id = source_id[source_i]
        target_id = target_id[target_i]
        source_instance_id = source_instance_id[source_i]
        target_instance_id = target_instance_id[target_i]
        score = distances[source_i][target_i]
        yield (source_id, source_instance_id, target_id, target_instance_id,
               score)


class MnemonicHistogramMatch(HistogramMatch):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_hist'


class OpcodeHistogramMatch(HistogramMatch):
  vector_type = 'opcode_histogram'
  match_type = 'opcode_histogram'

match_list = [AssemblyHashMatch, MnemonicHashMatch, MnemonicHistogramMatch,
              OpcodeHistogramMatch]
