# authentication/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
    path('user/', views.user_dashboard, name='user_dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('otp_verify/', views.otp_verify_page, name='otp_verify'),  # Assuming otp_verify_page is correct
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('delete_users/', views.delete_users, name='delete_users'),
    path('add_user/', views.add_user, name='add_user'),
    path('users_list/', views.users_list, name='users_list'),
    path('manage_users/', views.manage_users, name='manage_users')
]