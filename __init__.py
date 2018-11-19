from ajenti.api import *
from ajenti.plugins import *
from ajenti.ui import *


info = PluginInfo(
    title='LetsEncrypt',
    icon=None,
    dependencies=[
        PluginDependency('main'),
    ],
)


def init():
    import main