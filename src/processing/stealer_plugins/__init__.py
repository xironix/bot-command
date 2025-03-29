"""
Stealer plugins package.

This package contains plugins for various stealer malware families.
Each plugin implements a specific parser for a known stealer format.
"""

from src.processing.stealer_plugins.base import StealerParserPlugin
from src.processing.stealer_plugins.redline import RedLineParser
from src.processing.stealer_plugins.risepro import RiseProParser
from src.processing.stealer_plugins.lumma import LummaParser
from src.processing.stealer_plugins.vidar import VidarParser
from src.processing.stealer_plugins.stealc import StealCParser
from src.processing.stealer_plugins.snake import SnakeStealerParser
from src.processing.stealer_plugins.xworm import XWormParser
from src.processing.stealer_plugins.vip import VIPStealerParser

# Register all available plugins
AVAILABLE_PLUGINS = [
    RedLineParser(),
    RiseProParser(),
    LummaParser(),
    VidarParser(),
    StealCParser(),
    SnakeStealerParser(),
    XWormParser(),
    VIPStealerParser()
]

__all__ = [
    'StealerParserPlugin',
    'AVAILABLE_PLUGINS',
    'RedLineParser',
    'RiseProParser',
    'LummaParser',
    'VidarParser',
    'StealCParser',
    'SnakeStealerParser',
    'XWormParser',
    'VIPStealerParser'
]