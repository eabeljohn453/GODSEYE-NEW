from django.db import models

class DetectedObject(models.Model):
    class_label = models.CharField(max_length=50)  # e.g., "gun", "knife"
    timestamp = models.DateTimeField(auto_now_add=True)
    confidence = models.FloatField()
    x1 = models.IntegerField()
    y1 = models.IntegerField()
    x2 = models.IntegerField()
    y2 = models.IntegerField()
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['class_label']),
        ]

    def __str__(self):
        return f"{self.class_label} at {self.timestamp}"