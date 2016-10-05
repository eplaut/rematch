from django.utils.timezone import now
from django.db.models import F
from models import Task, Vector, Match
import matches

from celery import shared_task


@shared_task
def match(file_id, project_id):
  # recording the task has started
  task = Task.objects.filter(task_id=match.request.id)
  task_id = task.only('id')[0].id
  task.update(status=Task.STATUS_STARTED, progress_max=len(matches.match_list))

  print("Running task {}".format(match.request.id))
  # TODO: order might be important here
  try:
    for match_type in matches.match_list:
      print(match_type)
      start = now()
      vectors_filter = Vector.objects.filter(type=match_type.vector_type)
      source_vectors = vectors_filter.filter(file_id=file_id)
      target_vectors = vectors_filter
      if project_id:
        target_vectors = target_vectors.filter(file_id__project_id=project_id)
      target_vectors = target_vectors.exclude(file_id=file_id)
      if source_vectors.count() and target_vectors.count():
        match_objs = gen_match_objs(task_id, match_type, source_vectors,
                                    target_vectors)
        Match.objects.bulk_create(match_objs)
      print("\tTook: {}".format(now() - start))

      task.update(progress=F('progress') + 1)
  except Exception:
    task.update(status=Task.STATUS_FAILED, finished=now())
    raise

  task.update(status=Task.STATUS_DONE, finished=now())


def gen_match_objs(task_id, match_type, source_vectors, target_vectors):
  matches = match_type.match(source_vectors, target_vectors)
  for source, source_instance, target, target_instance, score in matches:
    mat = Match(task_id=task_id, from_vector_id=source, to_vector_id=target,
                from_instance_id=source_instance,
                to_instance_id=target_instance,
                score=score, type=match_type.match_type)
    yield mat
