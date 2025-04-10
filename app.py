from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64, uuid, boto3, os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# AWS S3 Configuration
AWS_ACCESS_KEY = 'AKIA4VDBMBF3HSC4QIHQ'
AWS_SECRET_KEY = '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'
BUCKET_NAME = 'tanmaysarode2203145bucket'

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name='ap-south-1')

def upload_to_s3(message_id, cipher_text, nonce):
    filename = f"messages/{message_id}.json"
    content = {
        "cipher_text": base64.b64encode(cipher_text).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "timestamp": datetime.utcnow().isoformat()
    }
    s3.put_object(Bucket=BUCKET_NAME, Key=filename,
                  Body=str(content), ContentType='application/json')
    return filename

def download_from_s3(message_id):
    filename = f"messages/{message_id}.json"
    obj = s3.get_object(Bucket=BUCKET_NAME, Key=filename)
    content = eval(obj['Body'].read().decode())
    return (
        base64.b64decode(content["cipher_text"]),
        base64.b64decode(content["nonce"])
    )

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    shared_key = PBKDF2(data['shared_key'], b'salt', dkLen=32)
    cipher = AES.new(shared_key, AES.MODE_EAX)
    cipher_text, tag = cipher.encrypt_and_digest(data['text'].encode())

    message_id = str(uuid.uuid4())
    upload_to_s3(message_id, cipher_text, cipher.nonce)

    return jsonify({"message_id": message_id})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    message_id = data['message_id']
    shared_key = PBKDF2(data['shared_key'], b'salt', dkLen=32)

    cipher_text, nonce = download_from_s3(message_id)
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(cipher_text).decode()

    return jsonify({"plain_text": plain_text})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

