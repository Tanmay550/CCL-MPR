from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64, uuid, boto3, json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# AWS S3 Configuration (make sure to store these in environment variables in production)
AWS_ACCESS_KEY = 'AKIA4VDBMBF3HSC4QIHQ'
AWS_SECRET_KEY = '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'
BUCKET_NAME = 'tanmaysarode2203145bucket'

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name='ap-south-1'
)

def upload_to_s3(message_id, cipher_text, nonce):
    filename = f"messages/{message_id}.json"
    content = {
        "cipher_text": base64.b64encode(cipher_text).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "timestamp": datetime.utcnow().isoformat()
    }
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=filename,
        Body=json.dumps(content),
        ContentType='application/json'
    )
    return filename

def download_from_s3(message_id):
    filename = f"messages/{message_id}.json"
    obj = s3.get_object(Bucket=BUCKET_NAME, Key=filename)
    content = json.loads(obj['Body'].read().decode())
    return (
        base64.b64decode(content["cipher_text"]),
        base64.b64decode(content["nonce"])
    )

@app.route('/')
def home():
    return '🔐 Secure Flask Encryption API is running on EC2!'

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        shared_key = PBKDF2(data['shared_key'], b'salt', dkLen=32)
        cipher = AES.new(shared_key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(data['text'].encode())

        message_id = str(uuid.uuid4())
        upload_to_s3(message_id, cipher_text, cipher.nonce)

        return jsonify({"message_id": message_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.get_json()
    print("Incoming decrypt request:", data)

    message_id = data.get('message_id')
    shared_key = data.get('shared_key')

    if not message_id or not shared_key:
        print("Missing message_id or shared_key")
        return jsonify({'error': 'Missing message_id or shared_key'}), 400

    s3_key = f"encrypted/{message_id}.json"
    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=s3_key)
    except Exception as e:
        print(f"S3 object not found: {s3_key}")
        return jsonify({'error': 'Message not found'}), 400

    enc_data = json.loads(obj['Body'].read().decode('utf-8'))
    print("Expected key:", enc_data.get('shared_key'))
    print("Provided key:", shared_key)

    if shared_key != enc_data.get('shared_key'):
        print("Key mismatch")
        return jsonify({'error': 'Invalid shared key'}), 400

    try:
        iv = base64.b64decode(enc_data['iv'])
        cipher_text = base64.b64decode(enc_data['cipher_text'])
        cipher = AES.new(shared_key.encode('utf-8'), AES.MODE_CFB, iv)
        plain_text = cipher.decrypt(cipher_text).decode('utf-8')
        return jsonify({'plain_text': plain_text}), 200
    except Exception as e:
        print("Decryption error:", e)
        return jsonify({'error': 'Decryption failed'}), 400



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
