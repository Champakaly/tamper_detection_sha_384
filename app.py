import os
from flask import Flask, render_template, request, url_for
import requests
from PIL import Image
from flask import send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__, static_url_path='/static')


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def rotate_right(val, n):
    return (val >> n) | (val << (64 - n))

def sha384_padding(message_len):
    padding_len = (896 - (message_len * 8 + 128) % 896) % 896
    padding = b'\x80' + b'\x00' * (padding_len // 8) + message_len.to_bytes(16, byteorder='big')
    return padding

def sha384_process_block(block, h):
    w = [0] * 80

    for i in range(16):
        w[i] = int.from_bytes(block[i * 8:(i + 1) * 8], byteorder='big')

    for i in range(16, 80):
        w[i] = (rotate_right(w[i - 2], 19) ^ rotate_right(w[i - 2], 61) ^ (w[i - 2] >> 6)) + \
               w[i - 7] + \
               (rotate_right(w[i - 15], 1) ^ rotate_right(w[i - 15], 8) ^ (w[i - 15] >> 7)) + \
               w[i - 16]

    a, b, c, d, e, f, g, hh = h

    for i in range(80):
        temp1 = hh + ((rotate_right(e, 14) ^ rotate_right(e, 18) ^ rotate_right(e, 41)) + (e & f ^ ~e & g) + 0x428a2f98d728ae22 + w[i])
        temp2 = (rotate_right(a, 28) ^ rotate_right(a, 34) ^ rotate_right(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))
        hh = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = (a + temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

    return [(x + y) & 0xFFFFFFFFFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

def sha384_hash(data):
    data_len = len(data) * 8
    data += sha384_padding(data_len)

    h = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
        0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    ]

    for i in range(0, len(data), 128):
        block = data[i:i + 128]
        h = sha384_process_block(block, h)

    return ''.join(format(x, '016x') for x in h)

def hash_image(image_path):
    img = Image.open(image_path)
    img_data = img.tobytes()
    return sha384_hash(img_data)

def check_tampering(image_path):
    # Replace 'your_image_path.jpg' with the actual path of your image file
    
    
    # Open the image
    img = Image.open(image_path)

    # Hash the entire image
    full_image_hash = hash_image(image_path)
    print("SHA-384 Hash of the full image:", full_image_hash)

    # Separate image channels and hash each channel
    r_channel, g_channel, b_channel = img.split()
    r_hash = sha384_hash(r_channel.tobytes())
    g_hash = sha384_hash(g_channel.tobytes())
    b_hash = sha384_hash(b_channel.tobytes())

    print("SHA-384 Hash of the Red channel:", r_hash)
    print("SHA-384 Hash of the Green channel:", g_hash)
    print("SHA-384 Hash of the Blue channel:", b_hash)

    # Create connected hashes
    connected_hash = sha384_hash((full_image_hash + r_hash + g_hash + b_hash).encode())
    print("Connected Hash:", connected_hash)
    return connected_hash


@app.route('/')
def index():
    # Get the absolute path of the current script's directory
    script_directory = os.path.dirname(os.path.realpath(__file__))

    # Generate URLs for the images in the static folder
    original_image_url = url_for('static', filename='original.jpg')
    tampered_image_url = url_for('static', filename='tamper.jpg')

    return render_template('index.html', original_image_url=original_image_url, tampered_image_url=tampered_image_url)

@app.route('/check_tampering', methods=['POST'])
def check_tampering_route():
    print("Entering check_tampering_route")
    # Get the file objects from the form
    original_image_file = request.files['original_image']
    tampered_image_file = request.files['tampered_image']

    # Check if the files are allowed
    if original_image_file and allowed_file(original_image_file.filename) and tampered_image_file and allowed_file(tampered_image_file.filename):
        # Save the uploaded files
        original_image_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(original_image_file.filename))
        tampered_image_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(tampered_image_file.filename))
        
        original_image_file.save(original_image_path)
        tampered_image_file.save(tampered_image_path)

        # Perform tampering check using the uploaded images
        chash1 = check_tampering(original_image_path)
        chash2 = check_tampering(tampered_image_path)

        if chash1 == chash2:
            result = "Image not tampered"
        else:
            result = "Image tampered"
        print("Exiting check_tampering_route")
        return render_template('result.html', result=result)
    else:
        result = "Invalid file format. Please upload images in JPG, JPEG, PNG, or GIF format."
        print("Exiting check_tampering_route")
        return render_template('result.html', result=result)
    

def download_image(image_url, filename):
     try:
        response = requests.get(image_url, stream=True)
        response.raise_for_status()

        with open(filename, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        return filename
     except requests.exceptions.RequestException as e:
        # Print detailed error information
        print(f"Error downloading image: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response content: {e.response.text}")
        return None
     


if __name__ == '__main__':
     # Ensure the 'uploads' folder exists
    uploads_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'uploads')
    if not os.path.exists(uploads_folder):
        os.makedirs(uploads_folder)

    app.run(debug=True)
    

