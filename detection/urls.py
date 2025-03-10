from django.urls import path
from . import views

app_name = 'detection'  # Define the namespace

urlpatterns = [
    path('video_feed/', views.video_feed, name='video_feed'),
   
]