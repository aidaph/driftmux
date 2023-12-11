import logging
from os import path
from sys import stdout

from collections import namedtuple

class Logger:

    def __init__(self, host, level="INFO"):
        self.level = level
        self.logger = logging.getLogger("scan IFCA")
        self.logger.setLevel(self.level)
        
        out_handler = logging.StreamHandler(stdout)
        filename = '/var/log/security/auditbbox/'+'{}.log'.format(host)
        self.file_handler = logging.FileHandler(filename)
        print("se ha creado el fichero {}".format(filename))
        formatter = logging.Formatter('%(message)s')
        out_handler.setFormatter(formatter)
        self.logger.addHandler(out_handler)
        #self.logger.addHandler(self.file_handler)
        
    def info(self, *args, **kwargs):
        self.logger.info(*args, **kwargs)

    def debug(self, *args, **kwargs):
        self.logger.debug(*args, **kwargs)

    def error(self, *args, **kwargs):
        self.logger.error(*args, **kwargs)



Color = namedtuple("Color", ["RED", "BLUE", "CYAN", "GREEN", "YELLOW", "GRAY", "BOLD", "RESET"])
COLOR = Color(
    "\033[1;31m",  # red
    "\033[1;34m",  # blue
    "\033[1;36m",  # cyan
    "\033[1;32m",  # green
    "\033[93m",    # yellow
    "\033[1;30m",  # gray
    "\033[;1m",    # bold
    "\033[0;0m"    # reset
)

ColoredCombos = namedtuple("ColoredCombos", ["INFO", "GOOD", "BAD", "NOTIFY"])
COLORED_COMBOS = ColoredCombos(
    "{}[#]{}".format(COLOR.BLUE, COLOR.RESET),
    "{}[v]{}".format(COLOR.GREEN, COLOR.RESET),
    "{}[x]{}".format(COLOR.RED, COLOR.RESET),
    "{}[!]{}".format(COLOR.YELLOW, COLOR.RESET))