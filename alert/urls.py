from django.urls import path
from .views import send_alert

urlpatterns = [
    path('send-alert/', send_alert, name='send_alert'),
]
