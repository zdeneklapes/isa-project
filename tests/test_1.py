import os
import filecmp
import time
import subprocess
from pathlib import Path
import pytest
from pathlib import Path
from subprocess import PIPE, STDOUT, run, call

# #############################################################################
# Settings
# #############################################################################
TESTS_DIR = Path(__file__).parent
DATA_IN_DIR = os.path.join(TESTS_DIR, 'data-in')
DATA_OUT_DIR = os.path.join(TESTS_DIR, 'data-out')
DATA_OUT_T1_DIR = os.path.join(TESTS_DIR, 'data-out/1/2')
ROOT_DIR = TESTS_DIR.parent
dns_sender_exe = os.path.join(ROOT_DIR, 'dns_sender')
dns_receiver_exe = os.path.join(ROOT_DIR, 'dns_receiver')


# #############################################################################
# Fixtures
# #############################################################################
@pytest.fixture
def go_to_root_dir(request):
    os.chdir(ROOT_DIR)
    yield
    os.chdir(request.config.invocation_dir)


@pytest.fixture
def compile_project(go_to_root_dir):
    assert call(["make", "clean"]) == 0
    assert call(["make"]) == 0
    assert call(["make", "sender"]) == 0
    assert call(["make", "receiver"]) == 0
    assert os.path.exists(dns_sender_exe)
    assert os.path.exists(dns_receiver_exe)


@pytest.fixture
def run_receiver(compile_project):
    child_proc = subprocess.Popen([dns_receiver_exe, 'example.com', './data/data_subdir'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, )
    time.sleep(1)  # wait receiver starts
    assert not child_proc.poll(), child_proc.stdout.read().decode("utf-8")  # Check it started successfully
    yield child_proc  # go to testing
    child_proc.terminate()  # Shut it down at the end of the pytest session


@pytest.fixture
def clean_data_out_folder():
    call(['rm', '-rfd', DATA_OUT_DIR])


# #############################################################################
# Tests
# #############################################################################

@pytest.mark.parametrize(
    "up_stream_dns_ip, base_host, dst_filepath, src_filepath",
    [
        (['-u', '127.0.0.1'], 'example.com', 'args_test/input1.txt', os.path.join(DATA_IN_DIR, 'input1.txt'))
    ]

)
def test_arguments_sender(compile_project, run_receiver, up_stream_dns_ip, base_host, dst_filepath, src_filepath):
    """ dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH] """
    assert call([dns_sender_exe, *up_stream_dns_ip, base_host, dst_filepath, src_filepath]) == 0
    assert call([dns_sender_exe, base_host, *up_stream_dns_ip, dst_filepath, src_filepath]) == 0
    assert call([dns_sender_exe, base_host, dst_filepath, *up_stream_dns_ip, src_filepath]) == 0
    assert call([dns_sender_exe, base_host, dst_filepath, src_filepath, *up_stream_dns_ip]) == 0


@pytest.mark.parametrize(
    "up_stream_dns_ip, base_host, dst_filepath, src_filepath",
    [
        pytest.param(['-u', '127.0.0.1'], 'example.com', '4/5/6/output1.txt',
                     os.path.join(DATA_IN_DIR, 'input1.txt')),
        # pytest.param(['-u', '127.0.0.1'], 'example.com', '4/5/6/output2.txt',
        #              os.path.join(DATA_IN_DIR, 'input2.txt')),
        # pytest.param(['-u', '127.0.0.1'], 'example.com', '4/5/6/output2.txt',
        #              os.path.join(DATA_IN_DIR, 'input2_1.txt')),
        # pytest.param(['-u', '127.0.0.1'], 'example.com', '4/5/6/output3.txt',
        #              os.path.join(DATA_IN_DIR, 'input3.txt')),
    ]

)
def test_file_transfer(clean_data_out_folder, compile_project, run_receiver, up_stream_dns_ip, base_host, dst_filepath, src_filepath):
    """ dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH] """
    # Run Sender
    assert call([dns_sender_exe, *up_stream_dns_ip, base_host, dst_filepath, src_filepath]) == 0

    # Compare files
    out_file = os.path.join(DATA_OUT_T1_DIR, dst_filepath)
    in_file = os.path.join(DATA_IN_DIR, src_filepath)
    try:
        assert filecmp.cmp(in_file, out_file)
    except FileNotFoundError as e:
        assert 0, f"{e}:\n{in_file}\n{out_file}"


@pytest.mark.xfail
def test_file_transfer_loss_packet():
    assert NotImplementedError
