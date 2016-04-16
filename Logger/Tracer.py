import os
import sys
import traceback

class Tracer(object):
    def __init__(self, is_trace_on=False):
        self.is_trace_on = is_trace_on
        self.writers = []

    def enable(self):
        self.is_trace_on = True

    def disable(self):
        self.is_trace_on = False

    def _get_caller_module(self):
        stack = traceback.extract_stack()
        entry = stack[-3]
        module_name = os.path.basename(entry[0]).split('.py')[0]
        return module_name
    
    def trace(self, message):
        if self.is_trace_on:
            for writer in self.writers:
                writer.write('%s: %s\n' % (self._get_caller_module(),
                                           message))
                writer.flush()

class PrintTracer(Tracer):
    def __init__(self, is_trace_on=False):
        super(PrintTracer, self).__init__(is_trace_on)
        self.writers.append(sys.stderr)

class FileTracer(Tracer):
    def __init__(self, file_name, is_trace_on=False):
        super(FileTracer, self).__init__(is_trace_on)
        self.trace_file = file(file_name, 'a+')
        self.writers.append(self.trace_file)

    def __del__(self):
        self.trace_file.close()

class PrintAndFileTracer(FileTracer):
    def __init__(self, file_name, is_trace_on=False):
        super(PrintAndFileTracer, self).__init__(file_name, is_trace_on)
        self.writers.append(sys.stderr)
