"""
Client entry point — delegates to app.client.client module.

Run with:
    python -m app.client
    or
    python app/client.py
"""

from app.client.client import main

if __name__ == "__main__":
    main()
