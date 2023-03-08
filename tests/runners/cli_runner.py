from subprocess import run, PIPE, STDOUT
from re import compile

class CLIRunner(object):

    def __init__(self):
        self.runner = None
        self.cmd = None
        # regexp to split a string by the spaces but avoid splitting strings enclosed in a double or single quotes
        self.split_regex = compile(r'(?:[\"\'].*?[\"\']|\S)+')

    def runcommand(self, cmd):
        self.cmd = cmd
        cmd_items = list(map(lambda x: x.strip('["\']'), self.split_regex.findall(cmd)))
        self.runner = run(cmd_items, stdout=PIPE, stderr=STDOUT, universal_newlines=True, shell=False)

        return self.runner
