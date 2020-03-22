import logging
import os
from pathlib import Path

logPath = Path(os.path.expanduser("~/.local/share/scarlett/scarlett.log"))
try:
    os.mkdir(logPath.parent)
except FileExistsError:
    pass

# TODO make logger print to stdout as well as write in the log file.

LOG_FORMAT = (
    "%(asctime)s"
    # "%(relativeCreated)6d"
    " [%(threadName)s]"
    " [%(module)s:%(funcName)s:%(lineno)d]"
    " [%(levelname)-5.5s]"
    "  %(message)s"
)

logFormatter = logging.Formatter(LOG_FORMAT)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)

fileHandler = logging.FileHandler(str(logPath.absolute()))
fileHandler.setFormatter(logFormatter)

logger = logging.getLogger("scarlett")
logger.setLevel(logging.DEBUG)
logger.addHandler(consoleHandler)
logger.addHandler(fileHandler)
