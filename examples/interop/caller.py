from pathlib import Path
import sys

from galeikan_bridge import Galeikan


module = Path(__file__).with_name("main.gak")
research = Galeikan().module(module, allow_python=sys.executable)
print(research.report(20))
