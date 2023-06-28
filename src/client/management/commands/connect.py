import argparse
import cmd
import re
from typing import Union

from client.services import Client, Session, Chat, GroupChat, AdminGroupChat

from django.core.management.base import BaseCommand


class ChatShell(cmd.Cmd):
    intro = 'Welcome to the Chat shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, chat: Chat, command: BaseCommand):
        self.prompt = f'(chat {chat.session.user_id} -> {chat.other_user_id} {chat.get_emoticons()}) '
        super().__init__()
        self.chat = chat
        self.command = command

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = f'(chat {self.chat.session.user_id} -> {self.chat.other_user_id} {self.chat.get_emoticons()}) '
        return super().postcmd(stop, line)

    def do_exit(self, inp):
        self.stdout.write(self.command.style.SUCCESS('Closing chat') + '\n')
        return True

    def do_send(self, inp):
        try:
            self.chat.send_message(inp)
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_refresh_dh_key(self, inp):
        try:
            self.chat.session.refresh_dh_key()
            self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')


class GroupChatShell(cmd.Cmd):
    intro = 'Welcome to the GroupChat shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, chat: Union[GroupChat, AdminGroupChat], command: BaseCommand):
        self.prompt = f'(groupchat {chat.session.user_id} -> {chat.group_id}) '
        super().__init__()
        self.chat = chat
        self.command = command

    def do_exit(self, inp):
        self.stdout.write(self.command.style.SUCCESS('Closing groupchat') + '\n')
        return True

    def do_send(self, inp):
        try:
            self.chat.send_message(inp)
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_refresh_dh_key(self, inp):
        try:
            self.chat.session.refresh_dh_key()
            self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_members(self, inp):
        self.stdout.write(self.command.style.SUCCESS(self.chat.session.user_id) + '\n')
        for member in self.chat.other_members:
            self.stdout.write(self.command.style.SUCCESS(member) + '\n')

    def do_emoticons(self, inp):
        for other_member, emoticons in self.chat.get_emoticons().items():
            self.stdout.write(self.command.style.SUCCESS(f'{other_member}: {emoticons}') + '\n')


class AdminGroupChatShell(GroupChatShell):

    def __init__(self, chat: AdminGroupChat, command: BaseCommand):
        super().__init__(chat, command)
        self.prompt = f'(groupchat {chat.session.user_id} -> {chat.group_id} [admin]) '

    def do_add_member(self, inp):
        try:
            self.chat.add_member(inp)
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_remove_member(self, inp):
        try:
            self.chat.remove_member(inp)
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')


class SessionShell(cmd.Cmd):
    intro = 'Welcome to the Session shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, session: Session, command: BaseCommand):
        self.prompt = f'(session {session.user_id}) '
        super().__init__()
        self.session = session
        self.command = command

    def do_exit(self, inp):
        self.stdout.write(self.command.style.SUCCESS('Closing session') + '\n')
        return True

    def do_list_online_users(self, inp):
        try:
            users = self.session.list_online_users()
            for user in users:
                self.stdout.write(self.command.style.SUCCESS(user) + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_refresh_dh_key(self, inp):
        try:
            self.session.refresh_dh_key()
            self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_list_chats(self, inp):
        try:
            chats = self.session.list_chats()
            for chat in chats:
                self.stdout.write(self.command.style.SUCCESS(chat) + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_start_chat(self, inp):
        match = re.match(r'^(?P<requestee>\w+)$', inp)
        if match:
            try:
                with self.session.start_chat(**match.groupdict()) as chat:
                    self.stdout.write(self.command.style.SUCCESS(f'Chat with {chat.other_user_id} started') + '\n')
                    ChatShell(chat, self.command).cmdloop()
            except Exception as e:
                self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
        else:
            self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')

    def do_create_group(self, inp):
        match = re.match(r'^(?P<id_>\w+)$', inp)
        if match:
            try:
                with self.session.create_group(**match.groupdict()) as chat:
                    self.stdout.write(self.command.style.SUCCESS(f'Group chat {chat.group_id} created') + '\n')
                    AdminGroupChatShell(chat, self.command).cmdloop()
            except Exception as e:
                self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
        else:
            self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')

    def do_list_groups(self, inp):
        try:
            for group in self.session.list_my_groups():
                self.stdout.write(self.command.style.SUCCESS(group) + '\n')
        except Exception as e:
            self.stdout.write(self.command.style.ERROR(str(e)) + '\n')

    def do_enter_group(self, inp):
        match = re.match(r'^(?P<group_id>\w+)$', inp)
        if match:
            try:
                with self.session.get_group_chat(**match.groupdict()) as chat:
                    self.stdout.write(self.command.style.SUCCESS(f'Group chat {chat.group_id} entered') +
                                      '\n')
                    if isinstance(chat, AdminGroupChat):
                        AdminGroupChatShell(chat, self.command).cmdloop()
                    else:
                        GroupChatShell(chat, self.command).cmdloop()
            except Exception as e:
                self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
        else:
            self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')


class MessengerShell(cmd.Cmd):
    intro = 'Welcome to the Messenger shell.   Type help or ? to list commands.\n'
    prompt = '(messenger client) '
    file = None

    def __init__(self, client: Client, command: BaseCommand):
        super().__init__()
        self.client = client
        self.command = command

    def do_exit(self, inp):
        self.command.stdout.write(self.command.style.SUCCESS('Bye') + '\n')
        return True

    def do_register(self, inp):
        match = re.match(r'^(?P<id_>\w+) (?P<password>\S+)$', inp)
        if match:
            try:
                self.client.register(**match.groupdict())
                self.stdout.write(self.command.style.SUCCESS('Registered') + '\n')
            except Exception as e:
                self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
        else:
            self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')

    def do_start_session(self, inp):
        match = re.match(r'^(?P<id_>\w+) (?P<password>\S+)$', inp)
        if match:
            try:
                with self.client.start_session(**match.groupdict()) as session:
                    self.stdout.write(self.command.style.SUCCESS('Session started') + '\n')
                    SessionShell(session, self.command).cmdloop()
            except RuntimeError as e:
                if e.args[0] != 'Client is closed':
                    raise
            except Exception as e:
                self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
        else:
            self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')


class Command(BaseCommand):
    help = 'Connects to the gRPC server'

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            'addr',
            help='The address of the gRPC server',
            default='localhost:50051',
            nargs='?',
        )

    def handle(self, addr: str,
               *args, **options):
        client = Client(addr)
        MessengerShell(client, self).cmdloop()
