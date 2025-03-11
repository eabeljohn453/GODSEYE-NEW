from django.http import StreamingHttpResponse
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
import cv2
from ultralytics import YOLO
from alert.views import process_threat_alert
from alert.models import ThreatMessage
from .models import DetectedObject
import time
from collections import deque
import math
import winsound
import logging
import numpy as np
import threading
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

logger = logging.getLogger(__name__)

model = YOLO("last.pt")
model.verbose = False
logger.debug(f"Model loaded with class names: {model.names}")

twilio_client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
video_source = getattr(settings, 'VIDEO_SOURCE', 0)
User = get_user_model()

def detection_state():
    last_detected = None
    last_detected_time = 0
    detection_history = deque(maxlen=10)
    threat_last_detected = {}
    threat_detection_history = deque(maxlen=10)
    DETECTION_TIMEOUT = 300.0
    THREAT_COOLDOWN = 10.0
    MIN_CONFIDENCE = 0.4
    CENTROID_THRESHOLD = 150
    CONFIDENCE_THRESHOLD = 0.3
    FRAME_SKIP = 1
    FRAME_RESOLUTION = (480, 360)

    def calculate_centroid(x1, y1, x2, y2):
        return ((x1 + x2) / 2, (y1 + y2) / 2)

    def is_new_detection(current_detection, last_detected, last_detected_time, history):
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
            last_detected = None
        if current_detection in history:
            is_new = False
        return is_new

    def is_new_threat(class_label, centroid, conf, last_threat_dict):
        current_time = time.time()
        if class_label not in last_threat_dict:
            last_threat_dict[class_label] = []
        last_threat_dict[class_label] = [
            (last_centroid, last_time, last_conf)
            for last_centroid, last_time, last_conf in last_threat_dict[class_label]
            if current_time - last_time <= THREAT_COOLDOWN
        ]
        for last_centroid, last_time, last_conf in last_threat_dict[class_label]:
            dx = centroid[0] - last_centroid[0]
            dy = centroid[1] - last_centroid[1]
            distance = math.sqrt(dx * dx + dy * dy)
            logger.debug(f"Threat {class_label}: Centroid distance: {distance:.2f}, Confidence diff: {abs(conf - last_conf):.2f}, Time since last: {current_time - last_time:.2f}")
            if (distance < CENTROID_THRESHOLD and abs(conf - last_conf) < CONFIDENCE_THRESHOLD):
                return False
        return True

    def send_threat_email_async(class_label, confidence, current_user):
        def send_email():
            subject = f"Threat Detected: {class_label.capitalize()}"
            message = f"A {class_label} was detected at {time.ctime()}.\nConfidence: {confidence:.2f}\nPlease take appropriate action."
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [current_user.email] if current_user else []
            if current_user and current_user.is_authenticated:
                managed_users = User.objects.filter(user_type='user', admin=current_user, email__isnull=False).exclude(email='')
                user_emails = [user.email for user in managed_users]
                if user_emails:
                    recipient_list.extend(user_emails)
            try:
                send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                logger.debug(f"Email sent: {subject} to {recipient_list}")
            except Exception as e:
                logger.error(f"Failed to send email: {str(e)}")
        threading.Thread(target=send_email, daemon=True).start()

    def make_threat_call_async(class_label, confidence):
        def make_call():
            for contact_number in settings.EMERGENCY_CONTACT_NUMBERS:
                try:
                    twiml = (
                        '<Response>'
                        '<Pause length="1"/>'
                        f'<Say voice="alice" loop="2">Alert: A {class_label} was detected at {time.ctime()}.Please take immediate action.</Say>'
                        '<Hangup/>'
                        '</Response>'
                    )
                    call = twilio_client.calls.create(twiml=twiml, to=contact_number, from_=settings.TWILIO_PHONE_NUMBER)
                    logger.debug(f"Initiated threat call to {contact_number}: Call SID {call.sid}")
                except TwilioRestException as e:
                    logger.error(f"Failed to make threat call to {contact_number}: {str(e)}")
        threading.Thread(target=make_call, daemon=True).start()

    def generate_frames(request):
        nonlocal last_detected, last_detected_time, detection_history
        nonlocal threat_last_detected, threat_detection_history
        camera = None
        try:
            camera = cv2.VideoCapture(video_source)
            if not camera.isOpened():
                logger.error(f"Camera failed to open on source: {video_source}")
                placeholder = cv2.putText(
                    cv2.zeros((FRAME_RESOLUTION[1], FRAME_RESOLUTION[0], 3), dtype="uint8"),
                    "Camera Unavailable",
                    (50, FRAME_RESOLUTION[1] // 2), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2
                )
                while True:
                    ret, buffer = cv2.imencode('.jpg', placeholder, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                    if not ret:
                        logger.error("Failed to encode placeholder to JPEG")
                        break
                    frame_bytes = buffer.tobytes()
                    yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                    time.sleep(0.1)
                return

            camera.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_RESOLUTION[0])
            camera.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_RESOLUTION[1])
            camera.set(cv2.CAP_PROP_FPS, 15)
            logger.debug(f"Camera opened successfully on source {video_source} with resolution {FRAME_RESOLUTION}")

            frame_count = 0
            skip_counter = 0

            while True:
                success, frame = camera.read()
                if not success:
                    logger.error("Failed to read frame from camera")
                    break

                frame_count += 1
                skip_counter += 1

                if skip_counter % FRAME_SKIP != 0:
                    ret, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                    if not ret:
                        logger.error("Failed to encode frame to JPEG")
                        continue
                    frame_bytes = buffer.tobytes()
                    yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                    continue

                frame = cv2.resize(frame, FRAME_RESOLUTION, interpolation=cv2.INTER_AREA)
                start_time = time.time()
                results = model.predict(frame, verbose=False, imgsz=FRAME_RESOLUTION[0], conf=MIN_CONFIDENCE)
                inference_time = time.time() - start_time
                logger.debug(f"YOLO inference took: {inference_time:.3f} seconds")

                for result in results:
                    for box in result.boxes:
                        cls = int(box.cls.item())
                        conf = float(box.conf.item())
                        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
                        class_label = model.names[cls].lower()
                        centroid = calculate_centroid(x1, y1, x2, y2)
                        current_detection = (class_label, centroid, conf)

                        if class_label in ["knife", "gun"]:
                            if is_new_detection(current_detection, last_detected, last_detected_time, detection_history):
                                logger.debug(f"New detection: {class_label}, confidence: {conf}, cls: {cls}")
                                last_detected = current_detection
                                last_detected_time = time.time()
                                detection_history.append(current_detection)

                        if class_label not in ["knife", "gun"] or conf < MIN_CONFIDENCE:
                            continue

                        logger.debug(f"Processing threat: {class_label} (confidence: {conf})")
                        if is_new_threat(class_label, centroid, conf, threat_last_detected):
                            try:
                                detection = DetectedObject.objects.create(
                                    class_label=class_label,
                                    confidence=conf,
                                    x1=x1, y1=y1,
                                    x2=x2, y2=y2,
                                    admin=request.user if request.user.is_authenticated else None
                                )
                                logger.debug(f"Logged threat detection: {class_label} (confidence: {conf})")
                            except Exception as e:
                                logger.error(f"Failed to save detection: {str(e)}")

                            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                            cv2.putText(frame, f"{class_label} ({conf:.2f})", 
                                        (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 
                                        0.5, (0, 0, 255), 2)
                            process_threat_alert(class_label)
                            send_threat_email_async(class_label, conf, request.user if request.user.is_authenticated else None)
                            make_threat_call_async(class_label, conf)
                            buzzer_enabled = request.session.get('buzzer_enabled', True)
                            if buzzer_enabled and request.user.is_authenticated:
                                try:
                                    winsound.Beep(1000, 200)
                                    logger.debug("Threat detected - Beep played!")
                                except Exception as e:
                                    logger.error(f"Failed to play beep sound: {str(e)}")
                            threat_last_detected[class_label].append((centroid, time.time(), conf))
                            threat_detection_history.append(current_detection)

                ret, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
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

    return generate_frames

generate_frames_with_state = detection_state()

@login_required(login_url='/auth/login/')
def video_feed(request):
    buzzer_enabled = request.GET.get('buzzer_enabled', 'true').lower() == 'true'
    request.session['buzzer_enabled'] = buzzer_enabled
    logger.debug(f"Buzzer enabled state: {buzzer_enabled}")
    return StreamingHttpResponse(
        generate_frames_with_state(request),
        content_type='multipart/x-mixed-replace; boundary=frame'
    )