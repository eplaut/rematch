from django.utils.timezone import now
from models import Task

from celery import shared_task


@shared_task
def match(file_id, project_id):
  task = Task.objects.filter(task_id=match.request.id)

  # recording the task has started
  task.update(status=Task.STATUS_STARTED)

  print("Running task {}".format(match.request.id))

  # TODO: finished=now
  task.update(status=Task.STATUS_DONE, finished=now())
