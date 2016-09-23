import json

# py2/3 compatibility, should be replaced with the six package
# once more compatibility issues arise
try:
  basestring
except NameError:
  basestring = (str, bytes)


class Vector:
  def __init__(self, offset, instance_id=None):
    self.instance_id = instance_id
    self.offset = offset
    self.data = None

  def serialize(self):
    if self.data is None:
      raise RuntimeError("vector data is None while serializing")
    if not isinstance(self.data, basestring):
      self.data = json.dumps(self.data)

    return {"instance": self.instance_id, "type": self.type,
            "type_version": self.type_version, "data": self.data}
