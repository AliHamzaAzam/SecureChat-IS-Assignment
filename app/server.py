"""
Server entry point — delegates to app.server.server module.

Run with:
    python -m app.server
    or
    python app/server.py
"""

from app.server.server import main

if __name__ == "__main__":
    main()
