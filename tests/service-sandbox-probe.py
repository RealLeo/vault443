"""Test-only launcher: apply a package unit's capabilities and syscall deny-list.

Runs only inside network-none test containers. Never touches the host service.
Discovery tests apply the exact unit capabilities; E2E uses filter-only mode
because its fixture needs CAP_SYS_ADMIN to create a private server namespace.
"""
import configparser
import ctypes
import errno
import os
import sys

assert os.path.exists('/.dockerenv')
assert os.environ.get('VAULT443_KERNEL_TEST') == '1' or os.environ.get('VAULT443_E2E_ISOLATED') == '1'
unit = configparser.ConfigParser(interpolation=None)
unit.read(sys.argv[1])
service = unit['Service']
if os.environ.get('VAULT443_CAPS_APPLIED') != '1' and os.environ.get('VAULT443_SANDBOX_FILTER_ONLY') != '1':
    caps = '-all' + ''.join(',+' + cap.removeprefix('CAP_').lower()
                           for cap in service['CapabilityBoundingSet'].split())
    os.environ['VAULT443_CAPS_APPLIED'] = '1'
    os.execv('/usr/bin/setpriv', ['setpriv', '--bounding-set=' + caps,
                                '--no-new-privs', sys.executable, *sys.argv])

deny = service.get('SystemCallFilter', '').split()
if deny:
    assert deny[0].startswith('~') and service['SystemCallErrorNumber'] == 'EPERM'
    deny[0] = deny[0][1:]
    seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    assert context
    numbers = [seccomp.seccomp_syscall_resolve_name(name.encode()) for name in deny]
    for nr in numbers:
        assert nr >= 0 and seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, nr, 0) == 0
    assert seccomp.seccomp_load(context) == 0
    seccomp.seccomp_release(context)
    libc = ctypes.CDLL(None, use_errno=True)
    for nr in numbers:
        ctypes.set_errno(0)
        assert libc.syscall(nr, -1, 0, 0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM
    print('Package debugging/memory syscall restrictions applied', flush=True)
os.execv(sys.argv[2], sys.argv[2:])
