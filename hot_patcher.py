class HotPatcher(object):
    '''
    Abstract class
    '''
    def __init__(self, binutils_prefix):
        self.binutils_prefix = binutils_prefix

    def read(self, virtual_address, size):
        raise NotImplemented()

    def write(self, virtual_address, data):
        raise NotImplemented()
