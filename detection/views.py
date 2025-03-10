# detection/views.py
from django.http import StreamingHttpResponse
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail  # Import Django's email functionality
from django.conf import settings
from django.contrib.auth import get_user_model  # To handle custom user models
import cv2
from ultralytics import YOLO
from alert.views import process_threat_alert
from alert.models import ThreatMessage
from .models import DetectedObject
import time
from collections import deque
import math
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Load the model and print available class names for debugging
model = YOLO("best.pt")
model.verbose = False  # Suppress YOLO's default output
logger.debug(f"Model loaded with class names: {model.names}")

video_source = getattr(settings, 'VIDEO_SOURCE', 0)

# Get the user model (custom or default)
User = get_user_model()

def detection_state():
    """Closure to manage detection state for all objects and threats."""
    last_detected = None  # Track last detected object (any class)
    last_detected_time = 0
    detection_history = deque(maxlen=10)  # History of all detections
    threat_last_detected = None  # Track last detected threat
    threat_last_detected_time = 0
    threat_detection_history = deque(maxlen=10)  # History of threat detections
    DETECTION_TIMEOUT = 300.0  # 5 minutes timeout
    MIN_CONFIDENCE = 0.5
    CENTROID_THRESHOLD = 200  # Require significant movement
    CONFIDENCE_THRESHOLD = 0.5  # Ignore minor confidence changes

    def calculate_centroid(x1, y1, x2, y2):
        """Calculate the centroid of a bounding box."""
        return ((x1 + x2) / 2, (y1 + y2) / 2)

    def is_new_detection(current_detection, last_detected, last_detected_time, history):
        """Check if the current detection is new based on centroid, confidence, and timeout."""
        is_new = True
        current_time = time.time()
        if last_detected and (current_time - last_detected_time) < DETECTION_TIMEOUT:
            last_class, last_centroid, last_conf = last_detected
            class_label, centroid, conf = current_detection
            dx = centroid[0] - last_centroid[0]
            dy = centroid[1] - last_centroid[1]
            distance = math.sqrt(dx * dx + dy * dy)
            logger.debug(f"Centroid distance: {distance:.2f}, Confidence diff: {abs(conf - last_conf):.2f}")
            if (class_label == last_class and 
                distance < CENTROID_THRESHOLD and 
                abs(conf - last_conf) < CONFIDENCE_THRESHOLD):
                is_new = False
        elif current_time - last_detected_time >= DETECTION_TIMEOUT:
            last_detected = None  # Reset if timeout expires
        if current_detection in history:
            is_new = False
        return is_new

    def send_threat_email(class_label, confidence, current_user):
        """Send an email notification for a detected threat."""
        subject = f"Threat Detected: {class_label.capitalize()}"
        message = (
            f"A {class_label} was detected at {time.ctime()}.\n"
            f"Confidence: {confidence:.2f}\n"
            f"Please take appropriate action."
        )
        from_email = settings.EMAIL_HOST_USER
        
        # Get emails of users associated with the current admin
        managed_users = User.objects.filter(
            user_type='user',
            admin=current_user,  # Assuming 'admin' is the field name for the associated admin
            email__isnull=False
        ).exclude(email='')
        user_emails = [user.email for user in managed_users]
        
        # Start with the current admin's email
        recipient_list = [current_user.email]
        
        # Add emails of users associated with this admin
        if user_emails:
            recipient_list.extend(user_emails)
        else:
            logger.warning("No users associated with this admin have valid emails, sending to admin only")

        logger.debug(f"Sending email from: {from_email} to: {recipient_list}")
        try:
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                fail_silently=False,
            )
            logger.debug(f"Email sent: {subject}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)} - Details: {type(e).__name__}")

    def generate_frames(request):
        nonlocal last_detected, last_detected_time, detection_history
        nonlocal threat_last_detected, threat_last_detected_time, threat_detection_history
        camera = None
        try:
            camera = cv2.VideoCapture(video_source)
            if not camera.isOpened():
                logger.error(f"Camera failed to open on source: {video_source}")
                raise ValueError(f"Cannot open video source: {video_source}")

            logger.debug(f"Camera opened successfully on source {video_source}")
            frame_count = 0
            while True:
                success, frame = camera.read()
                if not success:
                    logger.error("Failed to read frame from camera")
                    break

                frame_count += 1
                
                results = model.predict(frame, verbose=False)  # Use predict with verbose=False
                new_detection = False  # Flag to track if a new detection occurs

                for result in results:
                    for box in result.boxes:
                        cls = int(box.cls.item())
                        conf = float(box.conf.item())
                        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
                        class_label = model.names[cls].lower()  # Convert to lowercase for consistency
                        centroid = calculate_centroid(x1, y1, x2, y2)
                        current_detection = (class_label, centroid, conf)

                        # Only log new detections for threats with sufficient confidence
                        if class_label in ["knife", "gun"]:
                            if is_new_detection(current_detection, last_detected, last_detected_time, detection_history):
                                logger.debug(f"New detection: {class_label}, confidence: {conf}, cls: {cls}")
                                last_detected = current_detection
                                last_detected_time = time.time()
                                detection_history.append(current_detection)
                            else:
                                logger.debug(f"Duplicate detection skipped: {class_label}, confidence: {conf}")

                        # Process only threats (knife or gun)
                        if class_label not in ["knife", "gun"]:
                            continue

                        # Apply minimum confidence threshold for threats
                        if conf < MIN_CONFIDENCE:
                            continue

                        logger.debug(f"Processing threat: {class_label} (confidence: {conf})")
                        # Check if this is a new threat detection
                        if is_new_detection(current_detection, threat_last_detected, threat_last_detected_time, threat_detection_history):
                            new_detection = True
                            try:
                                detection = DetectedObject.objects.create(
                                    class_label=class_label,
                                    confidence=conf,
                                    x1=x1, y1=y1,
                                    x2=x2, y2=y2
                                )
                                logger.debug(f"Logged threat detection: {class_label} (confidence: {conf})")
                            except Exception as e:
                                logger.error(f"Failed to save detection to DetectedObject: {str(e)}")

                            # Draw and alert for new threat detections
                            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                            cv2.putText(frame, f"{class_label} ({conf:.2f})", 
                                      (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 
                                      0.5, (0, 0, 255), 2)
                            process_threat_alert(class_label)
                            # Send email to current admin and their associated users
                            send_threat_email(class_label, conf, request.user)
                            threat_last_detected = current_detection
                            threat_last_detected_time = time.time()
                            threat_detection_history.append(current_detection)

                ret, buffer = cv2.imencode('.jpg', frame)
                if not ret:
                    logger.error("Failed to encode frame to JPEG")
                    continue
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        except Exception as e:
            logger.error(f"Error in video processing: {str(e)}")
        finally:
            if camera is not None:
                camera.release()
                logger.debug("Camera released")

    # Return the generator function that accepts request
    return generate_frames

# Create the generator function with state
generate_frames_with_state = detection_state()

def video_feed(request):
    """View to return a streaming response for the video feed."""
    return StreamingHttpResponse(
        generate_frames_with_state(request),
        content_type='multipart/x-mixed-replace; boundary=frame'
    )