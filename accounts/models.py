from django.db import models
from django.contrib.auth.models import User
<<<<<<< HEAD
from django.utils import timezone

class UserProfile(models.Model):
    """Extended user profile with role and display information."""
    ROLE_CHOICES = [
        ('viewer', 'Viewer'),
        ('editor', 'Editor'),
        ('admin', 'Admin'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    display_name = models.CharField(max_length=100, blank=True)
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
        """Get the count of failed login attempts within the cooldown window."""
        cutoff_time = timezone.now() - timezone.timedelta(minutes=cooldown_minutes)
        return cls.objects.filter(
            username=username,
            timestamp__gte=cutoff_time
        ).count()

    @classmethod
    def record_failure(cls, username, ip_address=None):
        """Record a failed login attempt."""
        cls.objects.create(username=username, ip_address=ip_address)

    @classmethod
    def clear_attempts(cls, username):
        """Clear all failed login attempts for a user after successful login."""
        cls.objects.filter(username=username).delete()
=======

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    def __str__(self):
        return self.user.username
>>>>>>> assignment/fix-open-redirects
