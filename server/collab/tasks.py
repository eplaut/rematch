from django.utils.timezone import now
from django.db.models import F
from models import Task, Vector, Match
import matches

from celery import shared_task


@shared_task
def match():
  # recording the task has started
  task = Task.objects.filter(task_id=match.request.id)
  task.update(status=Task.STATUS_STARTED, progress=0,
              progress_max=len(matches.match_list))

  # get input parameters
  task_id, source_file, target_project, target_file = \
    task.values('id', 'source_file_id', 'target_project_id', 'target_file_id')

  base_source_vectors = Vector.objects.filter(file_id=source_file)
  base_target_vectors = Vector.objects.exclude(file_id=source_file)
  if target_project:
    base_target_vectors = base_target_vectors.filter(project_id=target_project)
  if target_file:
    base_target_vectors = base_target_vectors.filter(file_id=target_file)

  print("Running task {}".format(match.request.id))
  # TODO: order might be important here
  try:
    for match_type in matches.match_list:
      print(match_type)
      start = now()
      source_vectors = base_source_vectors.filter(type=match_type.vector_type)
      target_vectors = base_target_vectors.filter(type=match_type.vector_type)

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
