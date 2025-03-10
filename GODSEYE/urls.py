from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("authentication.urls")),
    path("detection/", include("detection.urls")),
    path("alert/", include("alert.urls")),
    path("history/", include("history.urls")),
]
