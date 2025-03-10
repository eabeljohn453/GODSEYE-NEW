# alert/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import ThreatMessage
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib import messages
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)

# Utility function to handle threat alerts (no request needed)
def process_threat_alert(class_label):
    try:
        # Temporary: Allow "person" for testing; revert to ["gun", "knife"] later
        if class_label in ["gun", "knife", "person"]:  # Added "person" for testing
            # Save to database
            threat = ThreatMessage.objects.create(
                message=f"Detected {class_label}",
                details=f"A {class_label} was detected at {timezone.now()}",
            )
            logger.debug(f"Saved threat to ThreatMessage: ID={threat.id}, Message={threat.message}, Details={threat.details}")

            # Send email to admins
            subject = f'New Threat Detected: {class_label}'
            message_body = f'A {class_label} has been detected in the video feed.\nTime: {timezone.now()}\nDetails: {threat.details}'
            from_email = settings.DEFAULT_FROM_EMAIL
            User = get_user_model()
            admin_emails = User.objects.filter(user_type='admin').values_list('email', flat=True)
            recipient_list = list(admin_emails)

            if recipient_list:
                send_mail(subject, message_body, from_email, recipient_list, fail_silently=False)
                logger.debug(f"Sent alert email for {class_label} to {recipient_list}")
            else:
                logger.warning("No admin emails found to send alert for {class_label}")
        else:
            logger.debug(f"No alert processed for {class_label} (not in ['gun', 'knife', 'person'])")
    except Exception as e:
        logger.error(f"Failed to process alert for {class_label}: {str(e)}")

@login_required(login_url='/auth/login/')
def send_alert(request):
    if request.user.user_type != 'admin':
        messages.error(request, "Access denied. Admins only.")
        return redirect('/auth/admin/')

    alerts = ThreatMessage.objects.all().order_by('-created_at')  # Order by creation time descending
    return render(request, 'alert/alerts.html', {'alerts': alerts})