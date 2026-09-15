#!/usr/bin/env python3
"""Chainsmith (python+cryptography edition): root/intermediate CAs and
server certs, forged and reissued on command. Operates on the same store/
as bash/chainsmith.sh (see pki/store.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pki.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
