import os

from pyfaka_app import create_app

app = create_app()


if __name__ == "__main__":
    debug = os.environ.get("PYFAKA_DEBUG", "1") == "1"
    host = os.environ.get("PYFAKA_HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("PYFAKA_PORT", "8099")), debug=debug, use_reloader=False)
