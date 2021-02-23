import sys
import types

from unittest import mock


class StubModule(types.ModuleType, mock.MagicMock):
    """ Uses a stub instead of loading libraries """

    def __new__(cls, name):
        module = sys.modules.get(name)
        if module is None:
            module = super().__new__(cls, name)

        if not isinstance(module, StubModule):
            raise RuntimeError("Module exists. Use mock.patch to stub it")

        return module

    def __init__(self, name: str):
        super().__init__(name)
        self.__name__ = name

    def __repr__(self):
        name = self.__name__
        mocks = ', '.join(set(dir(self)) - {'__name__'})
        return "<StubModule: %(name)s; mocks: %(mocks)s>" % locals()

    @classmethod
    def reg_stub(cls, module_name):
        module = cls(module_name)
        sys.modules[module_name] = module
        return module


# bcc do not required for tests
# and have much complexity to install
# skip it
bcc_stub = StubModule.reg_stub('bcc')
bcc_stub.BPF = object()

