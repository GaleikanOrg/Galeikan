"""Call a Galeikan module with ordinary Python attribute syntax."""

from pathlib import Path
import sys

from galeikan_bridge import Galeikan


binary = sys.argv[1] if len(sys.argv) > 1 else "galeikan"
research = Galeikan(binary).module(Path(__file__).with_name("python_callable.gak"))
print(research.twice(21))
print(research.echo(b"GAK"))
