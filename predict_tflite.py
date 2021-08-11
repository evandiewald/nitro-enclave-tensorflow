# predict_tflite.py

import tflite_runtime.interpreter as tflite
import numpy as np
from PIL import Image


# classify the image by invoking the lightweight tensorflow interpreter (installing full TF image is 2-3GB)
def classify_image_in_memory(image_bytes: bytes):
    # Load the user image.
    img = np.array(Image.frombytes('RGB', (600, 450), image_bytes).resize((224, 224)))
    img = (img - 127.5) / 127.5
    img = np.expand_dims(img, 0).astype('float32')

    # Load TFLite model and allocate tensors.
    print('loading .tflite model...')
    # TFLITE model was converted from the full h5 model stored here: https://github.com/uyxela/Skin-Lesion-Classifier/
    interpreter = tflite.Interpreter(model_path="skin_lesion_model.tflite")
    print('done.')
    interpreter.allocate_tensors()

    # Get input and output tensors.
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    # Test model on random input data.
    input_shape = input_details[0]['shape']

    interpreter.set_tensor(input_details[0]['index'], img)

    interpreter.invoke()

    # The function `get_tensor()` returns a copy of the tensor data.
    # Use `tensor()` in order to get a pointer to the tensor.
    output_data = interpreter.get_tensor(output_details[0]['index']).flatten()

    max_class = int(np.array(output_data).argmax())
    LABELS = [
        'Actinic Keratoses and Intraepithelial Carcinoma',
        'Basal Cell Carcinoma',
        'Benign Keratosis',
        'Dermatofibroma',
        'Melanoma',
        'Melanocytic Nevi',
        'Vascular Lesions'
    ]
    output = max_class.to_bytes(4, 'big')
    return output
