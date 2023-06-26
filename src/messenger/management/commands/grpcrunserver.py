import argparse
import errno
import os
import signal
import sys
from concurrent import futures
from datetime import datetime
from threading import Event
from typing import Optional

import grpc
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import autoreload


class GracefulKiller:
    kill_now = False

    def __init__(self):
        self.__event = Event()
        signal.signal(signal.SIGINT, self.__exit_gracefully)
        signal.signal(signal.SIGTERM, self.__exit_gracefully)

    def __exit_gracefully(self, signum, frame):
        self.__event.set()

    def wait(self):
        self.__event.wait()


class Command(BaseCommand):
    help = 'Runs the gRPC server'

    default_port = '50051'
    protocol = 'http'

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            'port',
            help='Optional port number',
            nargs='?',
            type=int,
        )
        parser.add_argument(
            '--noreload',
            help='Tells Django to NOT use the auto-reloader',
            action='store_false',
            dest='use_reloader',
        )
        parser.add_argument(
            '--num-workers',
            help='Number of gRPC workers',
            type=int,
            default=os.cpu_count(),
        )

    # noinspection PyAttributeOutsideInit
    def handle(self, port: Optional[int],
               *args, **options):
        self.port = port or self.default_port
        self.run(**options)

    def run(self, use_reloader: bool, **options):
        """Run the server, using the autoreloader if needed."""
        if use_reloader:
            self.killer = GracefulKiller()
            autoreload.run_with_reloader(self.inner_run, **options)
        else:
            self.inner_run(None, **options)

    def inner_run(self, *args, num_workers: int = os.cpu_count(), **options):
        autoreload.raise_last_exception()

        shutdown_message = options.get("shutdown_message", "")
        quit_command = "CTRL-BREAK" if sys.platform == "win32" else "CONTROL-C"

        self.check_migrations()
        now = datetime.now().strftime("%B %d, %Y - %X")
        self.stdout.write(now)
        self.stdout.write(
            (
                "Django version %(version)s, using settings %(settings)r\n"
                "Starting development gRPC server at %(protocol)s://[::]:%(port)s/\n"
                "Quit the server with %(quit_command)s."
            )
            % {
                "version": self.get_version(),
                "settings": settings.SETTINGS_MODULE,
                "protocol": self.protocol,
                "port": self.port,
                "quit_command": quit_command,
            }
        )

        try:
            server = grpc.server(futures.ThreadPoolExecutor(max_workers=num_workers))
            for app in settings.INSTALLED_APPS:
                try:
                    mod = __import__(app + '.services', fromlist=[''])
                    mod.grpc_handlers(server)
                    sys.stdout.write(f'Loaded {app}.services\n')
                except ImportError:
                    pass
            server.add_insecure_port(f'[::]:{self.port}')
            server.start()
            self.killer.wait()
            server.stop(0)
            os._exit(0)
        except OSError as e:
            # Use helpful error messages instead of ugly tracebacks.
            ERRORS = {
                errno.EACCES: "You don't have permission to access that port.",
                errno.EADDRINUSE: "That port is already in use.",
                errno.EADDRNOTAVAIL: "That IP address can't be assigned to.",
            }
            try:
                error_text = ERRORS[e.errno]
            except KeyError:
                error_text = e
            self.stderr.write("Error: %s" % error_text)
            # Need to use an OS exit because sys.exit doesn't work in a thread
            os._exit(1)
        except KeyboardInterrupt:
            if shutdown_message:
                self.stdout.write(shutdown_message)
            sys.exit(0)
