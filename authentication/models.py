from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    USER_TYPES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPES, default='user')
    admin = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        limit_choices_to={'user_type': 'admin'},
        related_name='managed_users'
    )
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=False, default='')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)