from django.core.management.base import BaseCommand
import cv2
import numpy as np
from openvino.runtime import Core
from detection.models import DetectedObject
from alert.models import ThreatMessage

class Command(BaseCommand):
    help = 'Run detection using OpenVINO'

    def handle(self, *args, **options):
        # Initialize OpenVINO
        ie = Core()
        model_path = "D:/GODSEYE/models/yolov5s.xml"
        model = ie.read_model(model=model_path)
        compiled_model = ie.compile_model(model=model, device_name="CPU")
        input_layer = compiled_model.input(0)
        output_layer = compiled_model.output(0)

        # Load class names
        with open("path/to/coco.names", "r") as f:
            class_names = [line.strip() for line in f]

        # Open video capture
        cap = cv2.VideoCapture(0)

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            # Preprocess and run inference (same as above)
            input_image = cv2.resize(frame, (640, 640))
            input_image = input_image.transpose((2, 0, 1))
            input_image = np.expand_dims(input_image, axis=0).astype(np.float32)
            result = compiled_model([input_image])[output_layer]
            detections = np.squeeze(result)

            for detection in detections:
                confidence = float(detection[4])
                if confidence > 0.5:
                    class_id = int(np.argmax(detection[5:]))
                    class_label = class_names[class_id]
                    x1, y1, x2, y2 = map(int, detection[0:4] * [frame.shape[1], frame.shape[0], frame.shape[1], frame.shape[0]])

                    detection_obj = DetectedObject(
                        class_label=class_label,
                        confidence=confidence,
                        x1=x1, y1=y1, x2=x2, y2=y2
                    )
                    detection_obj.save()
                    self.stdout.write(f"Saved detection to DetectedObject: {class_label} (confidence: {confidence})")

                    if class_label == 'person' and confidence > 0.9:
                        threat_message = ThreatMessage(
                            message=f"Threat detected: {class_label} with high confidence ({confidence:.2f})"
                        )
                        threat_message.save()
                        self.stdout.write(f"Saved threat message: {threat_message.message}")

            cv2.imshow("Detection", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

        cap.release()
        cv2.destroyAllWindows()
        self.stdout.write("Camera released")