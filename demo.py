from pathlib import Path
from client.submit import submit_binary

ROOT = Path(__file__).resolve().parent
submit_binary(str(ROOT / "samples" / "sample_pe.bin"), "https://localhost:5000")
