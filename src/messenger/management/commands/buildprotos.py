import glob
import subprocess

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Builds the protobuf files'

    def handle(self, *args, **options):
        proto_files = [
            file for file in glob.glob('./**/*.proto', recursive=True)
        ]
        result = subprocess.run(['python',
                                 '-m',
                                 'grpc_tools.protoc',
                                 '-I.',
                                 '--python_out=.',
                                 '--grpc_python_out=.',
                                 *proto_files],
                                capture_output=True,
                                text=True)
        if result.returncode != 0:
            raise CommandError(f'Failed to build protos: {result.stdout} {result.stderr}')
        proto_file_list = '\n'.join(proto_files)
        self.stdout.write(self.style.SUCCESS(f'Successfully built protos:\n{proto_file_list}'))
