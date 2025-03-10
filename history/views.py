from django.shortcuts import render
from alert.models import ThreatMessage
from detection.models import DetectedObject

def history_view(request):
    # Default sorting
    detection_history = DetectedObject.objects.all()
    
    # Get sort and order from query parameters
    sort_field = request.GET.get('sort', 'timestamp')  # Default to 'timestamp'
    order = request.GET.get('order', 'desc')  # Default to 'desc' (descending)
    
    # Validate sort field
    valid_fields = {
        'confidence': 'confidence',
        'timestamp': '-timestamp',  # Default descending
        'class_label': 'class_label'
    }
    sort_field = valid_fields.get(sort_field, '-timestamp')  # Fallback to '-timestamp'
    
    # Apply order if ascending is requested
    if sort_field in ['confidence', 'class_label'] and order == 'asc':
        sort_field = sort_field  # Remove '-' for ascending
    elif sort_field == '-timestamp' and order == 'asc':
        sort_field = 'timestamp'  # Remove '-' for ascending timestamp
    
    # Apply sorting
    detection_history = detection_history.order_by(sort_field)
    
    # Apply high confidence filter if requested
    if 'high_confidence' in request.GET:
        detection_history = detection_history.filter(confidence__gt=0.9)
    
    return render(request, 'history/history.html', {'detection_history': detection_history})

def latest_threat_view(request):
    latest_threat_message = ThreatMessage.objects.order_by('-created_at').first()
    context = {
        'latest_threat_message': latest_threat_message.message if latest_threat_message else None,
        'latest_threat_time': latest_threat_message.created_at if latest_threat_message else None
    }
    return render(request, 'history/latest_threat.html', context)