import uuid
import os
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from .validators import validate_max_file_size, validate_image_extension, validate_document_extension

def avatar_upload_path(instance, filename):
    """Rename avatar to UUID to prevent path traversal and collisions."""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('avatars/', filename)

def doc_upload_path(instance, filename):
    """Rename document to UUID."""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('documents/', filename)

class UserProfile(models.Model):
    """Extended user profile with role, display, bio, and media upload information."""
    ROLE_CHOICES = [
        ('viewer', 'Viewer'),
        ('editor', 'Editor'),
        ('admin', 'Admin'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    display_name = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    avatar = models.ImageField(
        upload_to=avatar_upload_path, 
        validators=[validate_max_file_size, validate_image_extension],
        null=True, blank=True
    )
    document = models.FileField(
        upload_to=doc_upload_path,
        validators=[validate_max_file_size, validate_document_extension],
        null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class LoginAttempt(models.Model):
    """Tracks failed login attempts for brute-force protection."""
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Failed login for '{self.username}' at {self.timestamp}"

    @classmethod
    def get_recent_failures(cls, username, cooldown_minutes):
        cutoff_time = timezone.now() - timezone.timedelta(minutes=cooldown_minutes)
        return cls.objects.filter(
            username=username,
            timestamp__gte=cutoff_time
        ).count()

    @classmethod
    def record_failure(cls, username, ip_address=None):
        cls.objects.create(username=username, ip_address=ip_address)

    @classmethod
    def clear_attempts(cls, username):
        cls.objects.filter(username=username).delete()

class AuditLog(models.Model):
    """Model for persistent audit logging of security-relevant events."""
    EVENT_TYPES = [
        ('registration', 'User Registration'),
        ('login_success', 'Login Success'),
        ('login_failure', 'Login Failure'),
        ('logout', 'User Logout'),
        ('privilege_change', 'Privilege Change'),
        ('password_change', 'Password Change'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    username_attempted = models.CharField(max_length=150, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        user_part = self.user.username if self.user else self.username_attempted or "Anonymous"
        return f"[{self.timestamp}] {self.event_type}: {user_part}"
