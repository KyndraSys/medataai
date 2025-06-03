import json
import hashlib
import hmac
import uuid
from flask import Flask, request
import pdfplumber
import PyPDF2
import os
import secrets
from datetime import datetime

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
DATABASE = "documents.json"
VERIFY_HISTORY = "verify_history.json"
HMAC_SECRET = secrets.token_hex(32)  # Secure key for HMAC

def generate_unique_code(doc_content):
    doc_id = str(uuid.uuid4())
    hash_input = doc_content + doc_id
    full_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    code = ''.join(c for c in full_hash.upper()[:16] if c.isalnum())
    while len(code) < 16:
        code += secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    return code[:16], doc_id

def generate_hmac_signature(doc_content):
    return hmac.new(HMAC_SECRET.encode('utf-8'), doc_content.encode('latin-1', errors='ignore'), hashlib.sha256).hexdigest()

def generate_unique_signature(timestamp):
    base_signature = f"kyndra-ceasar{timestamp}"
    increment = "00#"
    try:
        with open(DATABASE, "r") as f:
            db = json.load(f)
            existing_signatures = [doc.get("signature", "") for doc in db]
            while f"{base_signature}{increment}" in existing_signatures:
                num = int(increment[:-1]) + 1
                increment = f"{num:02d}#"
    except FileNotFoundError:
        pass
    return f"{base_signature}{increment}"

def extract_deep_metadata(pdf_path, filename):
    metadata = {"verification_status": "Valid"}
    try:
        with pdfplumber.open(pdf_path) as pdf:
            metadata["page_count"] = len(pdf.pages)
            metadata["text_length"] = len(pdf.pages[0].extract_text() or "")
        with open(pdf_path, "rb") as f:
            pdf_reader = PyPDF2.PdfReader(f)
            info = pdf_reader.metadata or {}
            metadata.update({
                "title": info.get("/Title", os.path.splitext(filename)[0]),
                "author": info.get("/Author", ""),
                "creator": info.get("/Creator", ""),
                "producer": info.get("/Producer", ""),
                "subject": info.get("/Subject", ""),
                "creation_date": info.get("/CreationDate", ""),
                "modification_date": info.get("/ModDate", "")
            })
    except Exception as e:
        print(f"Error extracting metadata: {e}")
        metadata["title"] = os.path.splitext(filename)[0]
    return metadata

def transfer_metadata(pdf_path, metadata, output_path, code):
    timestamp = datetime.now().strftime("%Y:%m:%d:%H:%M:%S")  # e.g., 2025:06:03:10:46:00
    signature = generate_unique_signature(timestamp)
    metadata["signature"] = signature
    
    reader = PyPDF2.PdfReader(pdf_path)
    writer = PyPDF2.PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    
    original_metadata = reader.metadata or {}
    writer.add_metadata(original_metadata)
    writer.add_metadata({
        "/KyndraSignature": signature,
        "/VerificationCode": code,  # Add 16-char code to metadata
        "/DocumentID": str(uuid.uuid4()),
        "/VerificationStatus": "Valid"
    })
    
    with open(output_path, "wb") as f:
        writer.write(f)
    return metadata, output_path

def save_metadata(metadata, code, doc_id, doc_hash, hmac_signature):
    metadata.update({
        "document_id": doc_id,
        "code": code,
        "document_hash": doc_hash,
        "signature": metadata["signature"],
        "hmac_signature": hmac_signature  # Store HMAC signature
    })
    try:
        with open(DATABASE, "r") as f:
            db = json.load(f)
    except FileNotFoundError:
        db = []
    db.append(metadata)
    with open(DATABASE, "w") as f:
        json.dump(db, f, indent=4)

def save_verification_history(metadata):
    try:
        with open(VERIFY_HISTORY, "r") as f:
            history = json.load(f)
    except FileNotFoundError:
        history = []
    history.append({
        "title": metadata["title"],
        "code": metadata["code"],
        "timestamp": datetime.now().strftime("%Y:%m:%d:%H:%M:%S")
    })
    with open(VERIFY_HISTORY, "w") as f:
        json.dump(history, f, indent=4)

@app.route("/upload", methods=["POST"])
def upload_pdf():
    if "file" not in request.files:
        return json.dumps({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return json.dumps({"error": "No file selected"}), 400
    
    if not file.filename.endswith(".pdf"):
        return json.dumps({"error": "Invalid file format. Please upload a PDF."}), 400
    
    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(input_path)
    
    metadata = extract_deep_metadata(input_path, filename)
    with open(input_path, "rb") as f:
        doc_content = f.read().decode('latin-1', errors='ignore')
    code, doc_id = generate_unique_code(doc_content)
    doc_hash = hashlib.sha256(doc_content.encode('latin-1', errors='ignore')).hexdigest()
    hmac_signature = generate_hmac_signature(doc_content)
    
    output_filename = f"{os.path.splitext(filename)[0]}.verified.pdf"
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)
    metadata, output_path = transfer_metadata(input_path, metadata, output_path, code)
    save_metadata(metadata, code, doc_id, doc_hash, hmac_signature)
    
    return json.dumps({"message": "Seal generated", "code": code, "output_path": output_path}), 200

@app.route("/verify", methods=["POST"])
def verify_code():
    if "file" in request.files:
        file = request.files["file"]
        if file and file.filename.endswith(".pdf"):
            filename = secure_filename(file.filename)
            upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(upload_path)
            
            with open(upload_path, "rb") as f:
                doc_content = f.read().decode('latin-1', errors='ignore')
                pdf_reader = PyPDF2.PdfReader(f)
                info = pdf_reader.metadata or {}
                signature_from_pdf = info.get("/KyndraSignature", "")
                code_from_pdf = info.get("/VerificationCode", "")  # Double verification
            
            hmac_signature = generate_hmac_signature(doc_content)
            
            try:
                with open(DATABASE, "r") as f:
                    db = json.load(f)
                for doc in db:
                    if (signature_from_pdf == doc.get("signature", "") and
                        code_from_pdf == doc.get("code", "") and
                        hmac_signature == doc.get("hmac_signature", "")):
                        save_verification_history(doc)
                        return json.dumps(doc), 200
                return json.dumps({"error": "Document not found, code mismatch, or integrity check failed"}), 404
            except FileNotFoundError:
                return json.dumps({"error": "Database not found"}), 500
        return json.dumps({"error": "Invalid file format"}), 400
    
    code = request.form.get("code")
    if code:
        try:
            with open(DATABASE, "r") as f:
                db = json.load(f)
            for doc in db:
                if doc["code"] == code:
                    save_verification_history(doc)
                    return json.dumps(doc), 200
            return json.dumps({"error": "Code not found"}), 404
        except FileNotFoundError:
            return json.dumps({"error": "Database not found"}), 500
    
    return json.dumps({"error": "No code or file provided"}), 400

@app.route("/history", methods=["GET"])
def get_history():
    try:
        with open(VERIFY_HISTORY, "r") as f:
            history = json.load(f)
        return json.dumps(history), 200
    except FileNotFoundError:
        return json.dumps([]), 200

def handler(event, context):
    with app.test_request_context(event["path"], method=event["httpMethod"], data=event["body"]):
        return app.full_dispatch_request()