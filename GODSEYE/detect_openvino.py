import cv2
import numpy as np
from openvino.runtime import Core
from detection.models import DetectedObject
from alert.models import ThreatMessage
# Initialize OpenVINO runtime
ie = Core()
model_path = "D:/GODSEYE/models/yolov5s.xml"
model = ie.read_model(model=model_path)
compiled_model = ie.compile_model(model=model, device_name="CPU")  # Use "GPU" or "MYRIAD" for other devices
input_layer = compiled_model.input(0)
output_layer = compiled_model.output(0)

# Load class names (replace with your YOLO class names file)
with open("path/to/coco.names", "r") as f:  # Update with your class names file
    class_names = [line.strip() for line in f]

# Open video capture
cap = cv2.VideoCapture(0)  # Use 0 for webcam or path to video file

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    # Preprocess frame
    input_image = cv2.resize(frame, (640, 640))  # Match model input shape
    input_image = input_image.transpose((2, 0, 1))  # HWC to CHW
    input_image = np.expand_dims(input_image, axis=0).astype(np.float32)  # Add batch dimension

    # Run inference
    result = compiled_model([input_image])[output_layer]
    detections = np.squeeze(result)  # Process output (adjust based on YOLOv5 output format)

    # Post-process detections (simplified; adjust for YOLOv5 output)
    for detection in detections:
        confidence = float(detection[4])  # Confidence score
        if confidence > 0.5:  # Threshold
            class_id = int(np.argmax(detection[5:]))  # Class ID
            class_label = class_names[class_id]
            x1, y1, x2, y2 = map(int, detection[0:4] * [frame.shape[1], frame.shape[0], frame.shape[1], frame.shape[0]])  # Scale to frame size

            # Save to database
            detection_obj = DetectedObject(
                class_label=class_label,
                confidence=confidence,
                x1=x1, y1=y1, x2=x2, y2=y2
            )
            detection_obj.save()
            print(f"Saved detection to DetectedObject: {class_label} (confidence: {confidence})")

            # Save threat message for high-confidence "person"
            if class_label == 'person' and confidence > 0.9:
                threat_message = ThreatMessage(
                    message=f"Threat detected: {class_label} with high confidence ({confidence:.2f})"
                )
                threat_message.save()
                print(f"Saved threat message: {threat_message.message}")

    # Display frame (optional)
    cv2.imshow("Detection", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
print("Camera released")