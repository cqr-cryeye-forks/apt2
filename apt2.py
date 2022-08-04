#!/usr/bin/env python3
"""
Standard Launcher for the SKIDY Framework
"""

import sys
import traceback

from core.framework import Framework


def main():
    framework = Framework()
    try:
        framework.run(sys.argv[1:])
    except KeyboardInterrupt:
        framework.ctrlc()
    except Exception as e:
        print_error(e)


def print_error(error: Exception):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print("*** print_tb:")
    traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
    print("\n\n*** print_exception:")
    traceback.print_exception(exc_type, exc_value, exc_traceback,
                              limit=2, file=sys.stdout)
    print("\n\n*** print_exc:")
    traceback.print_exc()
    # print "\n\n*** format_exc, first and last line:"
    # formatted_lines = traceback.format_exc().splitlines()
    # print formatted_lines[0]
    # print formatted_lines[-1]
    # print"\n\n***format_exception:"
    # print repr(traceback.format_exception(exc_type, exc_value, exc_traceback))
    # print"\n\n***extract_tb:"
    # print repr(traceback.extract_tb(exc_traceback))
    # print"\n\n***format_tb:"
    # print repr(traceback.format_tb(exc_traceback))
    # print"\n\n***tb_lineno:", exc_traceback.tb_lineno
    # print sys.exc_info()[0]
    # framework.cleanup()


if __name__ == "__main__":
    main()
