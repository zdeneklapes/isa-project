import os
import pytest
from pathlib import Path
from subprocess import PIPE, STDOUT, run, call


@pytest.fixture
def change_test_dir(request):
    os.chdir(request.config.rootdir)
    yield
    os.chdir(request.config.invocation_dir)


def test_arguments(change_test_dir):
    assert call("make") == 0
    assert call(['./sender', '-u', '127.0.0.1', 'example.com', 'data.txt', './data.txt']) == 0
    assert call(['echo', 'foo', '|', './sender', 'example.com', 'data.txt']) == 0

    # errors
    assert call(['./sender', '-u', '127.0.0.1', 'example.com', 'data.txt']) == 0  # TODO: Is this error
    assert call(['./sender', '-u', '127.0.0.1', 'example.com', 'data.txt', './data.txt', 'ff']) == 1
