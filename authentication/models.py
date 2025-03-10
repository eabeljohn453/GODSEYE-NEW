from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    USER_TYPES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPES, default='user')
    admin = models.ForeignKey(
        'self',  # Self-referential to CustomUser
        on_delete=models.CASCADE,  # Delete users if their admin is deleted
        null=True,  # Allow null for admins themselves
        blank=True,
        limit_choices_to={'user_type': 'admin'},  # Only admins can be linked
        related_name='managed_users'  # Allows reverse lookup (e.g., admin.managed_users)
    )
    email = models.EmailField()  # Remove unique=True to allow duplicate emails
    username = models.CharField(max_length=150, unique=False, default='')  # Allow non-unique usernames

    def __str__(self):
        return self.email  # Use email instead of username

    # Override save method to ensure username is set if empty
    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email  # Default username to email if not set
        super().save(*args, **kwargs)