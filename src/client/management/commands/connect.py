import argparse
import cmd
import re
from abc import abstractmethod, ABC
from datetime import datetime
from functools import wraps
from typing import Union, Optional, Callable

from django.core.management.base import BaseCommand

from client.services import Client, Session, Chat, GroupChat, AdminGroupChat


def command(pattern: Optional[str] = None, func: Optional[Callable] = None):
    @wraps(func)
    def wrapper(func):
        def inner(self: 'BaseShell', inp: str):
            match = re.match(pattern or r'^\s*$', inp)
            if match:
                try:
                    return func(self, **match.groupdict())
                except KeyboardInterrupt:
                    pass
                except EOFError:
                    return True
                except Exception as e:
                    self.stdout.write(self.command.style.ERROR(str(e)) + '\n')
            else:
                self.stdout.write(self.command.style.ERROR('Invalid command') + '\n')
                self.do_help('')

        return inner

    if func:
        return wrapper(func)
    return wrapper


class BaseShell(cmd.Cmd, ABC):

    def __init__(self, command: BaseCommand, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.command = command

    @abstractmethod
    def do_exit(self, inp):
        pass

    def cmdloop(self, *args, **kwargs):
        try:
            return super().cmdloop(*args, **kwargs)
        except KeyboardInterrupt:
            self.do_exit('')


class ChatShell(BaseShell):
    intro = 'Welcome to the Chat shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, chat: Chat, command: BaseCommand):
        self.prompt = f'({datetime.now()} chat {chat.session.user_id} -> ' \
                      f'{chat.other_user_id} {chat.get_emoticons()}) '
        super().__init__(command)
        self.chat = chat

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = f'({datetime.now()} chat {self.chat.session.user_id} -> ' \
                      f'{self.chat.other_user_id} {self.chat.get_emoticons()}) '
        return super().postcmd(stop, line)

    @command()
    def do_exit(self):
        self.stdout.write(self.command.style.SUCCESS('Closing chat') + '\n')
        return True

    @command(r'^(?P<message>.+)$')
    def do_send(self, message: str):
        self.chat.send_message(message)

    @command()
    def do_refresh_dh_key(self):
        self.chat.session.refresh_dh_key()
        self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')


class GroupChatShell(BaseShell):
    intro = 'Welcome to the GroupChat shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, chat: Union[GroupChat, AdminGroupChat], command: BaseCommand):
        self.prompt = f'({datetime.now()} groupchat {chat.session.user_id} -> {chat.group_id}) '
        super().__init__(command)
        self.chat = chat

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = f'({datetime.now()} groupchat {self.chat.session.user_id} -> {self.chat.group_id}) '
        return super().postcmd(stop, line)

    @command()
    def do_exit(self):
        self.stdout.write(self.command.style.SUCCESS('Closing groupchat') + '\n')
        return True

    @command(r'^(?P<message>.+)$')
    def do_send(self, message: str):
        self.chat.send_message(message)

    @command()
    def do_refresh_dh_key(self):
        self.chat.session.refresh_dh_key()
        self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')

    @command()
    def do_members(self):
        other_members = self.chat.other_members
        self.stdout.write(self.command.style.SUCCESS(self.chat.session.user_id) + '\n')
        for member in other_members:
            self.stdout.write(self.command.style.SUCCESS(member) + '\n')

    @command()
    def do_emoticons(self):
        for other_member, emoticons in self.chat.get_emoticons().items():
            self.stdout.write(self.command.style.SUCCESS(f'{other_member}: {emoticons}') + '\n')


class AdminGroupChatShell(GroupChatShell):

    def __init__(self, chat: AdminGroupChat, command: BaseCommand):
        super().__init__(chat, command)
        self.prompt = f'({datetime.now()} groupchat {chat.session.user_id} -> {chat.group_id} [admin]) '

    def postcmd(self, stop: bool, line: str) -> bool:
        self.prompt = f'({datetime.now()} groupchat {self.chat.session.user_id} -> {self.chat.group_id} [admin]) '
        return super().postcmd(stop, line)

    @command(r'^(?P<user_id>.+)$')
    def do_add_member(self, user_id: str):
        self.chat.add_member(user_id)

    @command(r'^(?P<user_id>.+)$')
    def do_remove_member(self, user_id: str):
        self.chat.remove_member(user_id)


class SessionShell(BaseShell):
    intro = 'Welcome to the Session shell.   Type help or ? to list commands.\n'
    file = None

    def __init__(self, session: Session, command: BaseCommand):
        self.prompt = f'(session {session.user_id}) '
        super().__init__(command)
        self.session = session

    @command()
    def do_exit(self):
        self.stdout.write(self.command.style.SUCCESS('Closing session') + '\n')
        return True

    @command()
    def do_list_online_users(self):
        users = self.session.list_online_users()
        for user in users:
            self.stdout.write(self.command.style.SUCCESS(user) + '\n')

    @command()
    def do_refresh_dh_key(self):
        self.session.refresh_dh_key()
        self.stdout.write(self.command.style.SUCCESS('DH key refreshed') + '\n')

    @command()
    def do_list_chats(self):
        chats = self.session.list_chats()
        for chat in chats:
            self.stdout.write(self.command.style.SUCCESS(chat) + '\n')

    @command(r'^(?P<requestee>\w+)$')
    def do_start_chat(self, requestee: str):
        with self.session.start_chat(requestee) as chat:
            self.stdout.write(self.command.style.SUCCESS(f'Chat with {chat.other_user_id} started') + '\n')
            ChatShell(chat, self.command).cmdloop()

    @command(r'^(?P<id_>\w+)$')
    def do_create_group(self, id_: str):
        with self.session.create_group(id_=id_) as chat:
            self.stdout.write(self.command.style.SUCCESS(f'Group chat {chat.group_id} created') + '\n')
            AdminGroupChatShell(chat, self.command).cmdloop()

    @command()
    def do_list_groups(self):
        for group in self.session.list_my_groups():
            self.stdout.write(self.command.style.SUCCESS(group) + '\n')

    @command(r'^(?P<group_id>\w+)$')
    def do_enter_group(self, group_id: str):
        with self.session.get_group_chat(group_id) as chat:
            self.stdout.write(self.command.style.SUCCESS(f'Group chat {chat.group_id} entered') +
                              '\n')
            if isinstance(chat, AdminGroupChat):
                AdminGroupChatShell(chat, self.command).cmdloop()
            else:
                GroupChatShell(chat, self.command).cmdloop()


class MessengerShell(BaseShell):
    intro = 'Welcome to the Messenger shell.   Type help or ? to list commands.\n'
    prompt = '(messenger client) '
    file = None

    def __init__(self, client: Client, command: BaseCommand):
        super().__init__(command)
        self.client = client

    @command()
    def do_exit(self):
        self.command.stdout.write(self.command.style.SUCCESS('Bye') + '\n')
        return True

    @command(r'^(?P<id_>\w+) (?P<password>\S+)$')
    def do_register(self, id_: str, password: str):
        self.client.register(id_, password)
        self.stdout.write(self.command.style.SUCCESS('Registered') + '\n')

    @command(r'^(?P<id_>\w+) (?P<password>\S+)$')
    def do_start_session(self, id_: str, password: str):
        try:
            with self.client.start_session(id_, password) as session:
                self.stdout.write(self.command.style.SUCCESS('Session started') + '\n')
                SessionShell(session, self.command).cmdloop()
        except RuntimeError as e:
            if e.args[0] != 'Client is closed':
                raise


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
