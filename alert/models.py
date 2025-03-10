# alert/models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ThreatMessage(models.Model):
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of message creation
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='threat_messages', null=True, blank=True)  # Optional admin association

    def __str__(self):
        return self.message

    class Meta:
        verbose_name = "Threat Message"
        verbose_name_plural = "Threat Messages"