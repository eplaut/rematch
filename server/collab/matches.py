import collections
import itertools
import json

import numpy as np
import sklearn as skl
import sklearn.preprocessing  # noqa flake8 importing as a different name
import sklearn.feature_extraction  # noqa flake8 importing as a different name


class Match:
  @classmethod
  def match(cls, source, target):
    raise NotImplementedError("Method match for vector type {} not "
                              "implemented".format(cls))


class HashMatch(Match):
  @classmethod
  def match(cls, source, target):
    # unique_values = set(source_dict.values())
    print(source.count(), target.count())
    flipped_rest = collections.defaultdict(list)
    # TODO: could be optimized by enumerating all identity matchs together
    target_values = target.values_list('id', 'instance_id', 'data').iterator()
    for target_id, target_instance_id, target_data in target_values:
      # TODO: could be optimized by uncommenting next line as most 'target'
      # values won't be present in 'source' list
      # if v in unique_values:
      flipped_rest[target_data].append((target_id, target_instance_id))
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
    source_values = itertools.izip(*source.values_list('id', 'instance_id',
                                                       'data'))
    target_values = itertools.izip(*target.values_list('id', 'instance_id',
                                                       'data'))

    source_ids, source_instance_ids, source_data = source_values
    target_ids, target_instance_ids, target_data = target_values
    dictvect = skl.feature_extraction.DictVectorizer()
    source_data = dictvect.fit_transform([json.loads(d) for d in source_data])
    target_data = dictvect.transform([json.loads(d) for d in target_data])
    source_matrix = skl.preprocessing.normalize(source_data, axis=1, norm='l1')
    target_matrix = skl.preprocessing.normalize(target_data, axis=1, norm='l1')
    print(type(source_matrix))
    print(source_matrix.shape)
    print(type(target_matrix))
    print(target_matrix.shape)
    for source_i in range(source_matrix.shape[0]):
      source_vector = source_matrix[source_i].toarray()
      source_id = source_ids[source_i]
      source_instance_id = source_instance_ids[source_i]
      print(source_i)

      for target_i in range(target_matrix.shape[0]):
        target_vector = target_matrix[target_i].toarray()
        target_id = target_ids[target_i]
        target_instance_id = target_instance_ids[target_i]

        score = np.linalg.norm(source_vector - target_vector)
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
