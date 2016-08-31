from django.utils.timezone import now
from djangp.db.models import F
from models import Task, Vector

from celery import shared_task


@shared_task
def match(file_id, project_id):
  # doing some preperations
  vector_types = [t[0] for t in Vector.TYPE_CHOICES]

  # recording the task has started
  task = Task.objects.filter(task_id=match.request.id)
  task.update(status=Task.STATUS_STARTED, progress_max=len(vector_types))

  print("Running task {}".format(match.request.id))
  # TODO: order might be important here
  for vector_type in vector_types:
      print(vector_type)
      vectors = Vector.objects.filter(type=vector_type)
      source_vectors = vectors.filter(file_id=file_id)
      target_vectors = vectors.filter(file_id__project_id=project_id,
                                      file_id__not=file_id)
      print(source_vectors)
      print(target_vectors)
      print(source_vectors.all())
      print(target_vectors.all())

      task.update(progress=F('progress') + 1)

  task.update(status=Task.STATUS_DONE, finished=now())
