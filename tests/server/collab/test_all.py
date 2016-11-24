import pytest
import json
from rest_framework import status

from django.db import models
import collab


collab_models = {'projects': {'name': 'test_project_1', 'private': False,
                              'description': 'description_1', 'files': []},
                 'files': {'instances': [], 'md5hash': 'H' * 32,
                           'name': 'file1', 'description': 'desc1'},
                 'tasks': {'source_file': 1, 'target_project': 1},
                 'instances': {'offset': 0, 'type': 'function', 'file': 1,
                               'vectors': []},
                 'vectors': {'instance': 1, 'type': 'hash', 'type_version': 0,
                             'data': 'data'}}

collab_model_objects = {'projects': [collab.models.Project(private=False)],
                        'files': [collab.models.File(name='reqf',
                                                     description='desc1',
                                                     md5hash='H' * 32)],
                        'tasks': ['projects', 'files',
                                  collab.models.Task(source_file_id=1,
                                                     target_project_id=1)],
                        'instances': ['files',
                                      collab.models.Instance(offset=0,
                                                             file_id=1)],
                        'vectors': ['instances',
                                    collab.models.Vector(instance_id=1,
                                                         file_id=1,
                                                         type='hash',
                                                         type_version=0,
                                                         data='data')]}

collab_model_reqs = {'projects': [],
                     'files': [],
                     'tasks': [collab.models.Project(private=False),
                               collab.models.File()],
                     'instances': [collab.models.File()],
                     'vectors': [collab.models.File(name='reqf',
                                                    description='desc1',
                                                    md5hash='H' * 32),
                                 collab.models.Instance(offset=0, file_id=1)]}


@pytest.mark.django_db
def create_models(model_list, user):
  objects_list = []
  for model in model_list:
    if isinstance(model, str):
      model_list.extend(create_models(collab_model_objects[model], user))
    else:
      model.owner = user
      model.save()
      objects_list.append(model)
  return objects_list


def assert_eq(a, b):
  if isinstance(a, list) and isinstance(b, list):
    assert len(a) == len(b)
    for a_item, b_item in zip(a, b):
      assert_eq(a_item, b_item)
  if isinstance(a, models.Model) and isinstance(b, dict):
    for k in b:
      d_value = b.__getitem__(k)
      o_value = a.__getattribute__(k)
      d_type = type(d_value)
      o_type = type(o_value)
      if d_type == o_type:
        assert d_value == o_value
      else:
        print("Skipped matching {k}: {d_value}({d_type}) ?? {o_value}({o_type})"
              "".format(k=k, d_value=d_value, d_type=d_type, o_value=o_value,
                        o_type=o_type))


def assert_response(response, status):
  print(response.content)
  assert response.status_code == status


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_empty_lists(client, model_name):
  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK)
  json_response = response.json()
  assert json_response == []


@pytest.mark.django_db
@pytest.mark.parametrize('model_name', collab_models.keys())
def test_model_guest_list(client, admin_user, model_name):
  # setup objects
  obj_list = create_models([model_name], admin_user)
  obj = obj_list[-1]

  response = client.get('/collab/{}/'.format(model_name))
  assert_response(response, status.HTTP_200_OK)
  dct_list = response.json()
  dct = dct_list[-1]
  assert_eq(dct, obj)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name, model_data', collab_models.items())
def test_model_guest_creation(client, model_name, model_data):
  response = client.post('/collab/{}/'.format(model_name),
                         data=json.dumps(model_data),
                         content_type="application/json")
  assert_response(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
@pytest.mark.parametrize('model_name, model_data', collab_models.items())
def test_model_creation(client, admin_client, admin_user, model_name,
                        model_data):
  create_models(collab_model_reqs[model_name], admin_user)

  response = admin_client.post('/collab/{}/'.format(model_name),
                               data=json.dumps(model_data),
                               content_type="application/json")

  assert_response(response, status.HTTP_201_CREATED)
  projects_created = [response.json()]

  response = client.get('/collab/{}/'.format(model_name))
  assert_eq(response.json(), projects_created)
