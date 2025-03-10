from django.db import models

class DetectionHistory(models.Model):
    detection_type = models.CharField(max_length=100)  # e.g., 'Threat', 'Landslide'
    detected_at = models.DateTimeField(auto_now_add=True)
    details = models.TextField()

    def __str__(self):
        return f"{self.detection_type} at {self.detected_at}"
