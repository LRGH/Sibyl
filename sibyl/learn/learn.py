import logging
import copy

from miasm2.core.objc import CTypesManagerNotPacked
from miasm2.core.ctypesmngr import CAstTypes
from miasm2.arch.x86.ctype import CTypeAMD64_unk

from sibyl.learn.replay import Replay
from sibyl.learn.findref import ExtractRef
from sibyl.commons import HeaderFile
from sibyl.config import config


class TestCreator(object):

    """Class used to create a test. Each instance is dedicated to only one learned function"""

    def __init__(self, functionname, address, program, header_filename,
                 tracer_class, generator_class, main_address, abicls, machine):
        """
        @functionname: name of the symbol of the learned function
        @address: address of the learned function in the program
        @program: program that uses the learned function
        @header_filename: file containing headers for the targeted function
        @tracer_class: class of the tracer used to run the program
        @generator_class: class of the generator used to create the test
        @main_address: address where the tracer has to begin, if none the tracer begins at the entry point
        @abicls: class of the ABI used by the program
        @machine: machine used by the program
        """
        self.functionname = functionname
        self.address = address
        self.program = program
        self.header_filename = header_filename
        self.tracer_class = tracer_class
        self.generator_class = generator_class
        self.main_address = main_address
        self.abicls = abicls
        self.machine = machine
        self.types = None

        self.learnexceptiontext = []

        self.logger = logging.getLogger("testcreator")
        console_handler = logging.StreamHandler()
        log_format = "%(levelname)-5s: %(message)s"
        console_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(console_handler)
        self.logger.setLevel(logging.INFO)

    def create_trace(self):
        '''Create the raw trace'''

        self.logger.info("Tracing the program")
        tracer = self.tracer_class(
            self.program, self.address, self.main_address, self.abicls, self.machine)
        self.trace = tracer.do_trace()

        # If the trace is empty, test can not be created
        if not self.trace:
            raise RuntimeError(
                "Test can not be created: function seems not to be called")

    def prune_snapshots(self):
        '''Prune available snapshots according to the pruning politics'''

        self.logger.info("Prunning snapshots: strategy %s, with %d elements " \
                         "keeped each time",
                         config.prune_strategy,
                         config.prune_keep)
        to_remove = []

        # Prune depending on the strategy
        if config.prune_strategy == "branch":
            already_keeped = {} # path -> seen number
            for snapshot in self.trace:
                path = frozenset(snapshot.paths.edges())
                current = already_keeped.get(path, 0)
                if current >= config.prune_keep:
                    # path of current snapshot is already known and enough
                    # occurences are already keeped
                    to_remove.append(snapshot)
                already_keeped[path] = current + 1
        else:
            raise ValueError("Unsupported strategy type: %s" % config.strategy)

        # Actually removed elements
        for snapshot in to_remove:
            self.trace.remove(snapshot)

        self.logger.info("Removed: %d, Keeped: %d", len(to_remove),
                         len(self.trace))


    def clean_trace(self):
        '''Try to remove all implementation dependant elements from the trace'''

        # Turn the trace into an implementation independent one
        self.logger.info("Cleaning snapshots")
        self.trace.clean()

    def test_trace(self):
        '''Find snapshots that do not recognize the learned function'''

        self.logger.info("Replaying cleaned snapshots")
        for i, snapshot in enumerate(self.trace):
            self.logger.info("Replaying snapshot %d", i)
            r = Replay(self, snapshot)
            if not r.run():
                self.learnexceptiontext += r.replayexception
                self.trace.remove(snapshot)

    def extract_refs(self):
        """Real extraction of input"""

        self.logger.info("Extract references from snapshots")
        for i, snapshot in enumerate(self.trace):
            self.logger.info("Extracting snapshot %d", i)
            r = ExtractRef(self, snapshot)
            if not r.run():
                self.learnexceptiontext += r.replayexception

    def create_test_from_trace(self):
        self.logger.info("Generating the final test class")
        generator = self.generator_class(self)
        return generator.generate_test()

    def parse_types(self):
        """Extract the prototype of the targeted function and associated type"""
        ctype_manager = CTypesManagerNotPacked(CAstTypes(), CTypeAMD64_unk())
        with open(self.header_filename) as fdesc:
            data = fdesc.read()
            self.headerfile = HeaderFile(data, ctype_manager)

        self.prototype = self.headerfile.functions[self.functionname]
        self.types = ctype_manager
        self.logger.info("Found prototype: %s" % self.prototype)

    def create_test(self):
        """
        Main function of the trace that is in charge of calling other methods in the right order
        Return a string that correspong to the code of the test class
        """

        self.parse_types()


        self.create_trace()

        self.prune_snapshots()

        self.clean_trace()

        self.test_trace()
        assert len(self.trace) > 0

        self.extract_refs()

        return self.create_test_from_trace()

