import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sniffy")


#class Logger:
#    def __init__(self, enabled, log_level) -> None:
#        self.log = ""
#        self.enabled = enabled
#        self.log_level = log_level
#
#    def log(self, line):
#        print(line)
#        self.log += line.join('\n')
#
#    def saveLog(self, file):
#        # TODO
#        raise NotImplementedError()