"""
trustfull - Active Directory trust attack toolkit

Usage:
  trustfull <module> [technique] [options]

Modules:
  badChild    Child-to-Parent intra-forest domain escalation

Run 'trustfull <module> --help' for module-specific help.
"""

import argparse
import sys

BANNER = r"""
  _                    _    __       _ _ 
 | |_ _ __ _   _ ___  | |_ / _|_   _| | |
 | __| '__| | | / __| | __| |_| | | | | |
 | |_| |  | |_| \__ \ | |_|  _| |_| | | |
  \__|_|   \__,_|___/  \__|_|  \__,_|_|_|

      For anyone with trust issues
 github.com/plur1bu5/trustfull
"""

MODULES = {
    'badChild':  'trustkit.attacks.bad_child',
    'enumerate': 'trustkit.attacks.enumerate',
}

MODULE_DESC = {
    'badChild':  'Child-to-Parent intra-forest domain escalation via ExtraSids',
    'enumerate': 'Enumerate all AD trust relationships with attack surface analysis',
}


def print_help():
    print(BANNER)
    print('Usage: trustfull <module> [options]\n')
    print('Modules:')
    for name, desc in MODULE_DESC.items():
        print('  %-12s %s' % (name, desc))
    print('\nRun \'trustfull <module> --help\' for module help.')
    print('Run \'trustfull <module> --techniques\' to list available techniques.\n')


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print_help()
        sys.exit(0)

    module_name = sys.argv[1]

    if module_name not in MODULES:
        print('[!] Unknown module: %s' % module_name)
        print('    Available: %s' % ', '.join(MODULES.keys()))
        sys.exit(1)

    # Delegate to module, passing remaining args
    import importlib
    mod = importlib.import_module(MODULES[module_name])
    sys.argv = ['trustfull %s' % module_name] + sys.argv[2:]
    mod.main()


if __name__ == '__main__':
    main()
