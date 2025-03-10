# authentication/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import CustomUser
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_backends
from django.core.cache import cache
import random
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
import logging
from detection.models import DetectedObject
from alert.models import ThreatMessage

# Configure logging
logger = logging.getLogger(__name__)

# Show login page
def login_page(request):
    return render(request, "authentication/login.html")

# Show OTP verification page
def otp_verify_page(request):
    return render(request, "authentication/otp_verify.html")
# authentication/views.py (snippet for dashboard views)
@login_required(login_url='/auth/login/')
@never_cache
def admin_dashboard(request):
    if request.user.user_type != 'admin':
        messages.error(request, "Access denied. Admins only.")
        return redirect('/auth/user/')
    detection_history = DetectedObject.objects.all().order_by('-timestamp')[:5]
    messages = ThreatMessage.objects.filter(admin=request.user).order_by('-created_at')[:5]
    users = CustomUser.objects.filter(admin=request.user, user_type="user")
    logger.debug(f"Admin {request.user.email} - Detection history count: {detection_history.count()}")
    logger.debug(f"Admin {request.user.email} - Messages count: {messages.count()}")
    logger.debug(f"Admin {request.user.email} - Detection history: {list(detection_history)}")
    logger.debug(f"Admin {request.user.email} - Messages: {list(messages)}")
    logger.debug(f"Admin {request.user.email} - Managed users: {list(users)}")
    context = {
        'detection_history': detection_history,
        'messages': messages,
        'users': users,
    }
    return render(request, "authentication/admin.html", context)

@login_required(login_url='/auth/login/')
@never_cache
def user_dashboard(request):  # Renamed for consistency
    if request.user.user_type != 'user':
        return redirect('/auth/admin/')
    associated_admin = request.user.admin
    if associated_admin:
        messages = ThreatMessage.objects.filter(admin=associated_admin).order_by('-created_at')[:5]
    else:
        messages = []
        logger.debug(f"User {request.user.email} has no associated admin")
    logger.debug(f"User {request.user.email} - Messages count: {messages.count()}")
    logger.debug(f"User {request.user.email} - Messages: {list(messages)}")
    context = {
        'messages': messages,
    }
    return render(request, "authentication/user.html", context)



# Login view with OTP generation for admins
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        logger.debug(f"Attempting login with email: {email}, password provided: {password}")

        try:
            users = CustomUser.objects.filter(email=email)
            if not users.exists():
                messages.error(request, "User not found")
                logger.debug(f"User not found for email: {email}")
                return render(request, "authentication/login.html")

            for user in users:
                if user.check_password(password):
                    logger.debug(f"Successfully authenticated user: {user.email}, user_type: {user.user_type}")
                    if user.user_type == 'admin':
                        otp = str(random.randint(100000, 999999))
                        request.session['otp'] = otp
                        request.session['email'] = email
                        request.session['password'] = password
                        request.session.set_expiry(300)

                        subject = 'Your Godseye Admin OTP'
                        message = f'Your OTP for logging into Godseye Admin is: {otp}\nThis OTP is valid for 5 minutes.'
                        from_email = settings.DEFAULT_FROM_EMAIL
                        recipient_list = [email]

                        try:
                            logger.debug(f"Sending OTP to {email} from {from_email}")
                            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                        except Exception as e:
                            logger.error(f"Failed to send OTP: {str(e)}")
                            messages.error(request, f"Failed to send OTP: {str(e)}")
                            return render(request, "authentication/login.html")

                        logger.debug("OTP sent successfully, redirecting to OTP verification")
                        return redirect('/auth/otp_verify/')
                    else:
                        user.backend = 'django.contrib.auth.backends.ModelBackend'
                        login(request, user)
                        logger.debug(f"Non-admin user logged in, redirecting to /auth/user/")
                        return redirect('/auth/user/')
            messages.error(request, "Invalid email or password")
            logger.debug(f"Invalid credentials for email: {email}")
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            messages.error(request, f"Login error: {str(e)}")

    return render(request, "authentication/login.html")

# Verify OTP for admin login
def verify_otp(request):
    if request.method == "POST":
        entered_otp = request.POST.get("otp")
        stored_otp = request.session.get('otp')
        email = request.session.get('email')
        stored_password = request.session.get('password')

        logger.debug(f"Verifying OTP - Entered: {entered_otp}, Stored: {stored_otp}, Email: {email}, Password: {stored_password}")

        if not all([entered_otp, stored_otp, email, stored_password]):
            messages.error(request, "Invalid OTP request. Please try logging in again.")
            logger.debug("Missing OTP, stored OTP, email, or password in session")
            return render(request, "authentication/otp_verify.html")

        if entered_otp == stored_otp:
            logger.debug("OTP verified successfully")
            User = get_user_model()
            try:
                user = User.objects.get(email=email)
                if user.check_password(stored_password) and user.user_type == 'admin':
                    user.backend = 'django.contrib.auth.backends.ModelBackend'
                    login(request, user)
                    logger.debug(f"User {user.email} logged in successfully")
                    del request.session['otp']
                    del request.session['email']
                    del request.session['password']
                    logger.debug("Redirecting to /auth/admin/")
                    return redirect('/auth/admin/')
                else:
                    messages.error(request, "Authentication failed. User type or password mismatch. Please try logging in again.")
                    logger.debug(f"Authentication failed for user with email: {email} - User type: {user.user_type}, Password check: {user.check_password(stored_password)}")
            except User.DoesNotExist:
                messages.error(request, "User not found. Please try logging in again.")
                logger.debug(f"User not found for email: {email}")
        else:
            messages.error(request, "Invalid OTP. Please try again or request a new one.")
            logger.debug(f"OTP mismatch - Entered: {entered_otp}, Stored: {stored_otp}")
        
        return render(request, "authentication/otp_verify.html")
    
    logger.debug("Redirecting to login due to GET request")
    return redirect('/auth/login/')

# Logout user
def logout_view(request):
    logout(request)
    logger.debug("User logged out, redirecting to /auth/login/")
    return redirect('/auth/login/')

# Add a new user (allow duplicate emails across and within different admins, no checks)
@login_required(login_url='/auth/login/')
@csrf_exempt
def add_user(request):
    if request.method == "POST":
        if request.user.user_type != 'admin':
            logger.debug("Access denied - Only admins can add users")
            return JsonResponse({"error": "Only admins can add users"}, status=403)

        name = request.POST.get("name")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not all([name, email, password]):
            logger.debug("Missing required fields for adding user")
            return JsonResponse({"error": "All fields (Name, Email, Password) are required"}, status=400)

        try:
            user = CustomUser.objects.create(
                username=email,
                email=email,
                password=make_password(password),
                user_type="user",
                admin=request.user
            )
            logger.debug(f"User added successfully: {email}")
            cache.delete(f"users_list_{request.user.id}")
            return JsonResponse({"message": "User added successfully"})
        except Exception as e:
            logger.error(f"Error adding user: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    
    logger.debug("Invalid request for adding user")
    return JsonResponse({"error": "Invalid request"}, status=400)

# Fetch and return the list of users managed by the current admin
@login_required(login_url='/auth/login/')
def users_list(request):
    if request.user.user_type != 'admin':
        logger.debug("Access denied - Only admins can view user list")
        return JsonResponse({"error": "Access denied"}, status=403)

    users = CustomUser.objects.filter(
        user_type="user",
        admin=request.user
    ).values("id", "username", "email")

    logger.debug(f"Returning user list for admin {request.user.id}: {list(users)}")
    return JsonResponse({"users": list(users)})

# Delete users managed by the current admin
@login_required(login_url='/auth/login/')
@csrf_exempt
def delete_users(request):
    if request.method == "POST":
        if request.user.user_type != 'admin':
            logger.debug("Access denied - Only admins can delete users")
            return JsonResponse({"error": "Access denied"}, status=403)

        data = json.loads(request.body)
        user_ids = data.get("users", [])

        try:
            deleted_users = CustomUser.objects.filter(
                id__in=user_ids,
                admin=request.user
            ).delete()
            if deleted_users[0] > 0:
                logger.debug(f"Deleted users: {user_ids}")
                cache.delete(f"users_list_{request.user.id}")
            return JsonResponse({"success": "Users deleted successfully"})
        except Exception as e:
            logger.error(f"Error deleting users: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    logger.debug("Invalid request for deleting users")
    return JsonResponse({"error": "Invalid request"}, status=400)

# Optional: Standalone manage_users view
@login_required(login_url='/auth/login/')
def manage_users(request):
    if request.user.user_type != 'admin':
        logger.debug("Access denied - Only admins can manage users")
        return redirect('/auth/user/')
    users = CustomUser.objects.filter(admin=request.user, user_type="user")
    logger.debug(f"Rendering manage_users for admin {request.user.id} with users: {users}")
    return render(request, 'authentication/manage_users.html', {'users': users})