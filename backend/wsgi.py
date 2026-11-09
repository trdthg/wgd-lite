"""
wgd-api production entrypoint.
    waitress-serve --listen=127.0.0.1:51822 --threads=2 wsgi:application
Background threads start here (not in app.py) so tests importing `app`
don't spawn loops.
"""
import app as app_module

application = app_module.app

app_module.start_threads()
