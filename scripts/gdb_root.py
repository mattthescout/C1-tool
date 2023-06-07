#!/usr/bin/python3
import os
import sys
import stat
import time
import json
import hashlib
from pathlib import Path

GRANT_EXPIRE_SEC = 2 * 60 * 60
TARGET_EXECUTABLE = '/usr/bin/gdb'
TMP_BIN_DIR = '/tmp/exec_as_root'


class ExecFailed(Exception):
    pass


def instance_hash(argv):
    command = ' '.join(argv)
    return hashlib.md5(command.encode()).hexdigest()


def write_c_code(path, argv):
    CODE_TEMPLATE = '''
    #include <time.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main(int argc, char *argv[])
    {
        int test_mode = (argc > 1);
        if (time(NULL) > (time_t)EXPIRE) {
            char path[1024] = { 0 };
            readlink("/proc/self/exe", path, sizeof(path));
            unlink(path);
            return !test_mode;
        }

        if (!test_mode)
            execl(PARAMS, NULL);

        return 0;
    }'''

    expire = time.time() + GRANT_EXPIRE_SEC
    params = [argv[0]] + argv
    params = json.dumps(params)[1:-1]
    content = CODE_TEMPLATE \
        .replace('EXPIRE', str(expire)) \
        .replace('PARAMS', params)

    with open(path, 'w') as f:
        f.write(content)


def system(cmd):
    is_ok = os.system(cmd) == 0
    if not is_ok:
        cmd_str = json.dumps(cmd)
        summary = 'failed to execute:'
        os.system(f'notify-send -- "{summary}" {cmd_str}')
        raise ExecFailed()


def build_instance(instance, argv):
    c_file = instance.with_suffix('.c')
    write_c_code(c_file, argv)
    compile_cmd = f'gcc -o {instance} {c_file}'
    system(compile_cmd)


def did_grant_root(file):
    fs = os.stat(file)
    root_own = (fs.st_uid == 0)
    uid_set = fs.st_mode & stat.S_ISUID
    return root_own and uid_set


def grant_root(file):
    setuid_cmd = f'chown root:root {file}; chmod 4111 {file}'
    pkexec_cmd = f'pkexec bash -c "{setuid_cmd}"'
    system(pkexec_cmd)


def main():
    bin_dir = Path(TMP_BIN_DIR)
    bin_dir.mkdir(exist_ok=True)

    argv = [TARGET_EXECUTABLE] + sys.argv[1:]
    instance = bin_dir / instance_hash(argv)

    if instance.exists():
        system(f'{instance} test')

    if not instance.exists():
        build_instance(instance, argv)

    if not did_grant_root(instance):
        grant_root(instance)

    os.execv(instance, [instance.name])


if __name__ == '__main__':
    try:
        main()
    except ExecFailed:
        exit(1)