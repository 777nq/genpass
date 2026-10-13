#!/usr/bin/env python3
"""
Backwards-compatible entrypoint forwarding to the CSPRNG genpass implementation.
"""
from genpass import generate_password, generate_passphrase, main

if __name__ == "__main__":
    main()
