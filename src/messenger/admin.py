from django.contrib import admin

from messenger.models import Configuration, ServerKey, Session, ChatRequest


@admin.register(Configuration)
class ConfigurationAdmin(admin.ModelAdmin):
    list_display = ('name', 'value')


@admin.register(ServerKey)
class ServerKeyAdmin(admin.ModelAdmin):
    readonly_fields = ('name', 'signature')
    list_display = ('name', 'signature')


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    readonly_fields = ('id', 'user', 'public_key_signature', 'shared_secret_signature',
                       'created_at', 'updated_at')
    list_display = ('id', 'user', 'shared_secret_signature', 'created_at', 'updated_at')


@admin.register(ChatRequest)
class ChatRequestAdmin(admin.ModelAdmin):
    readonly_fields = ('id', 'requester', 'requestee', 'created_at', 'updated_at', 'status')
    list_display = ('id', 'requester', 'requestee', 'created_at', 'updated_at', 'status')
