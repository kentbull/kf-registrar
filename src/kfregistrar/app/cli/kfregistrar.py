# -*- encoding: utf-8 -*-
"""
kfregistrar.app.cli.kfregistrar module

CLI entry point for the registrar operational network.
"""

import multicommand
from keri import help
from keri.app.directing import runController

from kfregistrar.app.cli import commands
from kfregistrar.core import serving


logger = help.ogler.getLogger()


def main():
    """Entry point for the kf-registrar CLI."""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return

    try:
        doers = args.handler(args)
        if not doers:
            return
        runController(doers=doers, expire=0.0, tock=serving.doistTock())
    except Exception as ex:
        print(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
