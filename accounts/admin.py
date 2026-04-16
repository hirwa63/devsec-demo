from django.contrib import admin
from .models import UserProfile, LoginAttempt, AuditLog

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'display_name')

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'username', 'ip_address')
    readonly_fields = ('timestamp', 'username', 'ip_address')

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'user', 'username_attempted', 'ip_address')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('username_attempted', 'details')
    readonly_fields = ('timestamp', 'event_type', 'user', 'username_attempted', 'ip_address', 'details')
