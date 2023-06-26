from django.contrib import admin

from messenger.models import Configuration, ServerKey, Session

# Register your models here.
admin.site.register(Configuration)


@admin.register(ServerKey)
class ServerKeyAdmin(admin.ModelAdmin):
    readonly_fields = ('name', 'signature')
    list_display = ('name', 'signature')


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    readonly_fields = ('id', 'user', 'public_key_signature', 'shared_secret_signature',
                       'created_at', 'updated_at')
    list_display = ('id', 'user', 'shared_secret_signature', 'created_at', 'updated_at')
