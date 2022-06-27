import os
import sys
import json

import pytest

sys.path.append(os.getcwd())

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "fixtures")


class Fixtures:
    """utility class to load JSON fixture files"""

    @classmethod
    def load_all(cls, dir_path):
        "Returns a mapping fixture data from directory: filename -> data"
        # map basename without suffix to file path
        files = [
            (os.path.basename(fname)[:-5], os.path.join(dir_path, fname))
            for fname in os.listdir(dir_path)
        ]
        return {name: cls.load(fpath) for (name, fpath) in files}

    @classmethod
    def load(cls, file_path):
        "Returns a JSON data from file"
        fp = open(file_path)
        return json.loads(fp.read())


@pytest.fixture
def flowers_fixtures():
    return Fixtures.load_all(FIXTURES_DIR)


def lambda_fixtures(patch=None):
    event_file = f"tests/lambda-event.json"
    context_file = f"tests/lambda-context.json"
    event = json.loads(open(event_file).read())
    # apply patch to the event object
    if patch:
        # lambda event: mutate event here... | apply direct dict update
        patch(event) if callable(patch) else event.update(**patch)

    context = json.loads(open(context_file).read())
    return event, context


def j(f):
    return json.loads(open(f).read())
