from django.db import models
from django.db.models.fields import files
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from collab.validators import IdbValidator


class Project(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=256)
  description = models.TextField()
  private = models.BooleanField()

  def __unicode__(self):
    return "Project: {}".format(self.name)
  __str__ = __unicode__

  class Meta:
    ordering = ('created',)


class File(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  owner = models.ForeignKey(User, db_index=True)
  project = models.ForeignKey(Project, null=True, related_name='files')
  name = models.CharField(max_length=256)
  description = models.TextField()
  md5hash = models.CharField(max_length=32, db_index=True,
                             validators=[MinLengthValidator(32)])
  file = files.FileField(upload_to="tasks", null=True,
                         validators=[IdbValidator])

  def __unicode__(self):
    return "File {}".format(self.name)
  __str__ = __unicode__


class Instance(models.Model):
  TYPE_EMPTY_DATA = 'empty_data'
  TYPE_DATA = 'data'
  TYPE_EMPTY_FUNCTION = 'empty_function'
  TYPE_FUNCTION = 'function'
  TYPE_CHOICES = ((TYPE_EMPTY_DATA, "Empty Data"),
                  (TYPE_DATA, "Data"),
                  (TYPE_EMPTY_FUNCTION, "Empty Function"),
                  (TYPE_FUNCTION, "Function"))

  owner = models.ForeignKey(User, db_index=True)
  file = models.ForeignKey(File, related_name='instances')
  type = models.CharField(max_length=16, choices=TYPE_CHOICES)
  offset = models.BigIntegerField()

  matches = models.ManyToManyField('Instance', symmetrical=True, through=Match)

  def __unicode__(self):
    return "{} instance {} at {}".format(self.get_type_display(), self.offset,
                                         self.file.name)
  __str__ = __unicode__


class Vector(models.Model):
  DUMMY = 'dummy'
  TYPE_HASH = 'hash'
  TYPE_ASSEMBLY_HASH = 'assembly_hash'
  TYPE_MNEMONIC_HASH = 'mnemonic_hash'
  TYPE_MNEMONIC_HIST = 'mnemonic_hist'
  TYPE_OPCODE_HIST = 'opcode_histogram'
  TYPE_CHOICES = ((DUMMY, "Dummy"),
                  (TYPE_HASH, "Hash"),
                  (TYPE_ASSEMBLY_HASH, "Assembly Hash"),
                  (TYPE_MNEMONIC_HASH, "Mnemonic Hash"),
                  (TYPE_MNEMONIC_HIST, "Mnemonic Hist"),
                  (TYPE_OPCODE_HIST, "Opcode Histogram"))

  instance = models.ForeignKey(Instance, related_name='vectors')
  type = models.CharField(max_length=16, choices=TYPE_CHOICES)
  type_version = models.IntegerField()
  data = models.TextField()

  def __unicode__(self):
    return "{} vector version {} for {}".format(self.get_type_display(),
                                                self.type_version,
                                                self.instance)
  __str__ = __unicode__


class Task(models.Model):
  STATUS_PENDING = 'pending'
  STATUS_STARTING = 'starting'
  STATUS_POPULATING = 'populating'
  STATUS_MATCHING = 'matching'
  STATUS_FINISHING = 'finishing'
  STATUS_DONE = 'done'
  STATUS_CHOICES = ((STATUS_PENDING, "Pending in Queue..."),
                    (STATUS_STARTING, "Started"),
                    ('-' + STATUS_STARTING, "Failed Starting"),
                    (STATUS_POPULATING, "Collecting Data..."),
                    ('-' + STATUS_POPULATING, "Failed Collecting Data..."),
                    (STATUS_MATCHING, "Comparing Elements..."),
                    ('-' + STATUS_MATCHING, "Failed Comparing Elements..."),
                    (STATUS_FINISHING, "Handling New Elements..."),
                    ('-' + STATUS_FINISHING, "Failed Handling New Elements..."),
                    (STATUS_DONE, "Done!"),
                    ('-' + STATUS_DONE, "General Failure"))
  ACTION_COMMIT = "commit"
  ACTION_MATCH = "match"
  ACTION_UPDATE = "update"
  ACTION_CLUSTER = "cluster"
  ACTION_CHOICES = ((ACTION_COMMIT, "Commit"),
                    (ACTION_MATCH, "Match"),
                    (ACTION_UPDATE, "Update"),
                    (ACTION_CLUSTER, "Cluster"))

  # store matched objects
  created = models.DateTimeField(auto_now_add=True)
  started = models.DateTimeField()
  finished = models.DateTimeField()

  owner = models.ForeignKey(User, db_index=True)
  status = models.CharField(max_length=16, choices=STATUS_CHOICES)
  action = models.CharField(max_length=16, choices=ACTION_CHOICES)


class Match(models.Model):
  task = models.ForeignKey(Task, db_index=True, related_name='matches')

  instance_source = models.ForeignKey(Instance)
  instance_target = models.ForeignKey(Instance)


#
# Anotations
#

class Annotation(models.Model):
  created = models.DateTimeField(auto_now_add=True)
  modified = models.DateTimeField(auto_now=True)
  owner = models.ForeignKey(User, db_index=True)
  instance = models.ForeignKey(Instance)

  offset = models.IntegerField()


class NameAnnotation(Annotation):
  name = models.CharField(max_length=256)


class CommentAnnotation(Annotation):
  comment = models.TextField()


class RptCommentAnnotation(Annotation):
  comment = models.TextField()


class AboveLineCommentAnnotation(Annotation):
  comment = models.TextField()


class BelowLineCommentAnnotation(Annotation):
  comment = models.TextField()
