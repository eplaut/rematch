from django.utils.timezone import now
from django.db.models import F
from models import Task, Vector, Match
import matches

from celery import shared_task


@shared_task
def match(file_id, project_id):
  # recording the task has started
  task = Task.objects.filter(task_id=match.request.id)
  task.update(status=Task.STATUS_STARTED, progress_max=len(matches.match_list))

  print("Running task {}".format(match.request.id))
  # TODO: order might be important here
  try:
    for match_type in matches.match_list:
      print(match_type)
      vectors_filter = Vector.objects.filter(type=match_type.vector_type)
      source_vectors = vectors_filter.filter(file_id=file_id)
      if project_id:
        target_vectors = vectors_filter.filter(file_id__project_id=project_id)
      target_vectors = target_vectors.exclude(file_id=file_id)
      print(source_vectors)
      print(target_vectors)
      print(source_vectors.all())
      print(target_vectors.all())
      match_results = match_type.match(source_vectors, target_vectors, task.id)
      match_objs = [Match(source, target, score=score,
                          type=match_type.match_type)
                    for source, target, score in match_results]
      Match.objects.bulk_create(match_objs)
      print(list(match_objs))

      task.update(progress=F('progress') + 1)
  except Exception as ex:
    task.update(status=Task.STATUS_FAILED, finished=now())
    raise ex

  task.update(status=Task.STATUS_DONE, finished=now())
