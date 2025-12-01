from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

app = Flask(__name__)

def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
    """Deriva chave e IV como o OpenSSL EVP_BytesToKey"""
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def encrypt_aes256(data, passphrase):
    """Criptografa dados usando AES-256 no formato CryptoJS"""
    salt = get_random_bytes(8)
    key, iv = evp_bytes_to_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padding_length = 16 - (len(data) % 16)
    padded_data = data + (chr(padding_length) * padding_length)
    encrypted = cipher.encrypt(padded_data.encode('utf-8'))
    
    result = b'Salted__' + salt + encrypted
    encrypted_b64 = base64.b64encode(result).decode('utf-8')
    encrypted_b64 = encrypted_b64.replace('+', '-').replace('/', '_').rstrip('=')
    
    return encrypted_b64

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "message": "API funcionando!"})

@app.route('/encrypt-certificate', methods=['POST'])
def encrypt_certificate():
    try:
        data = request.get_json()
        
        cert_base64 = data.get('cert_base64')
        senha = data.get('senha')
        chave_criptografia = data.get('chave_criptografia')
        
        if not cert_base64 or not senha or not chave_criptografia:
            return jsonify({
                "sucesso": False,
                "erro": "Campos obrigatórios: cert_base64, senha, chave_criptografia"
            }), 400
        
        cert_cripto = encrypt_aes256(cert_base64, chave_criptografia)
        senha_cripto = encrypt_aes256(senha, chave_criptografia)
        
        return jsonify({
            "sucesso": True,
            "pkcs12_cert": cert_cripto,
            "pkcs12_pass": senha_cripto,
            "mensagem": "Certificado criptografado com sucesso"
        })
        
    except Exception as e:
        return jsonify({
            "sucesso": False,
            "erro": str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
