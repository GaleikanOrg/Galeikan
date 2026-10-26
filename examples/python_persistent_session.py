"""Call one Galeikan module several times without reloading it."""

from pathlib import Path
import sys

from galeikan_bridge import Galeikan


binary = sys.argv[1] if len(sys.argv) > 1 else "galeikan"
script = Path(__file__).with_name("python_callable.gak")
with Galeikan(binary).session(script) as research:
    print(research.twice(21))
    print(research.echo(b"GAK"))
