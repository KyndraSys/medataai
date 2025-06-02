import hashlib
import json
import uuid
from flask import Flask, request, render_template, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import pdfplumber
import PyPDF2
import os
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ADMIN_PASSWORD = "kyndra_secure_2025"  # Replace with a secure password
DATABASE = "documents.json"

def generate_unique_code(doc_content):
    doc_id = str(uuid.uuid4())
    hash_input = doc_content + doc_id
    full_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    code = ''.join(c for c for c in full_hash.upper()[:16] if c.isalnum())
    while len(code) < 16:
        code += secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    return code[:16], doc_id

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

def transfer_metadata(pdf_path, metadata, output_path):
    timestamp = datetime.now().strftime("%Y:%m:%d:%H:%M:%S")  # e.g., 2025:06:02:17:41:00
    signature = f"kyndra-ceasar-{timestamp}"
    
    # Update title with kyndra-ceasar suffix
    if metadata["title"]:
        metadata["title"] = f"{metadata['title']} {signature}"
    
    reader = PyPDF2.PdfReader(pdf_path)
    writer = PyPDF2.PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    
    original_metadata = reader.metadata or {}
    writer.add_metadata(original_metadata)
    writer.add_metadata({
        "/Title": metadata["title"],
        "/KyndraSignature": signature,
        "/DocumentID": str(uuid.uuid4()),
        "/VerificationStatus": "Valid"
    })
    
    with open(output_path, "wb") as f:
        writer.write(f)
    return metadata, output_path

def save_metadata(metadata, code, doc_id, doc_hash):
    metadata.update({"document_id": doc_id, "code": code, "document_hash": doc_hash, "signature": metadata["signature"]})
    try:
        with open(DATABASE, "r") as f:
            db = json.load(f)
    except FileNotFoundError:
        db = []
    db.append(metadata)
    with open(DATABASE, "w") as f:
        json.dump(db, f, indent=4)

@app.route("/", methods=["GET", "POST"])
def upload_pdf():
    if request.method == "POST":
        password = request.form.get("password")
        if password != ADMIN_PASSWORD:
            flash("Invalid password")
            return redirect(url_for("upload_pdf"))
        
        if "file" not in request.files:
            flash("No file uploaded")
            return redirect(url_for("upload_pdf"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected")
            return redirect(url_for("upload_pdf"))
        
        if file and file.filename.endswith(".pdf"):
            filename = secure_filename(file.filename)
            input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(input_path)
            
            metadata = extract_deep_metadata(input_path, filename)
            if request.form.get("submit") == "Edit and Process":
                metadata.update({
                    "title": request.form.get("title", metadata["title"]),
                    "author": request.form.get("author", metadata["author"]),
                    "creator": request.form.get("creator", metadata["creator"]),
                    "producer": request.form.get("producer", metadata["producer"]),
                    "subject": request.form.get("subject", metadata["subject"])
                })
            
            with open(input_path, "rb") as f:
                doc_content = f.read().decode('latin-1', errors='ignore')
            code, doc_id = generate_unique_code(doc_content)
            doc_hash = hashlib.sha256(doc_content.encode('latin-1', errors='ignore')).hexdigest()
            
            output_filename = f"{os.path.splitext(filename)[0]}.verified.pdf"
            output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)
            metadata, output_path = transfer_metadata(input_path, metadata, output_path)
            save_metadata(metadata, code, doc_id, doc_hash)
            
            flash("Seal generated. Please add the code from the table to the PDF footer manually (e.g., 'Kyndra Systems Seal: <code>').")
            return send_file(output_path, as_attachment=True)
    
    try:
        with open(DATABASE, "r") as f:
            db = json.load(f)
    except FileNotFoundError:
        db = []
    return render_template("upload.html", documents=db)

@app.route("/verify", methods=["GET", "POST"])
def verify_code():
    if request.method == "POST":
        code = request.form.get("code")
        if code:
            try:
                with open(DATABASE, "r") as f:
                    db = json.load(f)
                for doc in db:
                    if doc["code"] == code:
                        return render_template("verify.html", metadata=doc)
                flash("Code not found")
            except FileNotFoundError:
                flash("Database not found")
            return redirect(url_for("verify_code"))
        
        if "file" in request.files:
            file = request.files["file"]
            if file and file.filename.endswith(".pdf"):
                filename = secure_filename(file.filename)
                upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(upload_path)
                
                with open(upload_path, "rb") as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    info = pdf_reader.metadata or {}
                    title_with_signature = info.get("/Title", "")
                
                try:
                    with open(DATABASE, "r") as f:
                        db = json.load(f)
                    for doc in db:
                        if "kyndra-ceasar" in title_with_signature and doc.get("signature", "") in title_with_signature:
                            return render_template("verify.html", metadata=doc)
                    flash("Document not found in database or signature mismatch")
                except FileNotFoundError:
                    flash("Database not found")
                return redirect(url_for("verify_code"))
            flash("Invalid file format. Please upload a PDF.")
            return redirect(url_for("verify_code"))
    
    return render_template("verify.html", metadata=None)

if __name__ == "__main__":
    app.run(debug=True)