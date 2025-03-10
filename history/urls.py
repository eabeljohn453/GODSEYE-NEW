from django.urls import path
from .views import history_view, latest_threat_view

app_name = 'history'

urlpatterns = [
    path('history/', history_view, name='history'),
    path('latest-threat/', latest_threat_view, name='latest_threat'),
]