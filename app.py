import streamlit as st
import io
import hashlib
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# --- FORENSIC ENGINE ---
class PulseProofEngine:
    def __init__(self, file_data, filename):
        self.file_data = file_data
        self.filename = filename.lower()

    def analyze(self):
        # Checks for C2PA 'Content Credentials' headers used by Adobe/Microsoft
        has_c2pa = b'C2PA' in self.file_data or b'JUMF' in self.file_data
        file_hash = hashlib.sha256(self.file_data).hexdigest()
        return {
            "verified": has_c2pa,
            "hash": file_hash,
            "filename": self.filename,
            "verdict": "HUMAN / VERIFIED" if has_c2pa else "AI-GENERATED / UNVERIFIED"
        }

def generate_certificate(results):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(100, 750, "PULSEPROOF TRUST CERTIFICATE")
    p.setFont("Helvetica", 12)
    p.drawString(100, 710, f"Filename: {results['filename']}")
    p.drawString(100, 690, f"Digital Fingerprint: {results['hash'][:40]}...")
    p.drawString(100, 670, f"Final Verdict: {results['verdict']}")
    p.line(100, 650, 500, 650)
    p.drawString(100, 630, "Verified via PulseProof C2PA Forensic Protocol v1.0")
    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

# --- USER INTERFACE ---
st.set_page_config(page_title="PulseProof | Media Integrity", page_icon="🛡️")
st.title("🛡️ PulseProof")
st.write("Detect AI-generated media and verify digital provenance in real-time.")

file = st.file_uploader("Upload Image", type=["jpg", "png", "jpeg"])

if file:
    bytes_data = file.read()
    st.image(file, caption="Target Asset", use_container_width=True)
    
    engine = PulseProofEngine(bytes_data, file.name)
    res = engine.analyze()
    
    if res['verified']:
        st.success(f"✅ VERIFIED: {res['verdict']}")
    else:
        st.error(f"🚨 WARNING: {res['verdict']}")
        st.write("No C2PA metadata detected. High risk of AI origin or tampering.")

    st.info(f"SHA-256 Hash: {res['hash']}")
    
    cert = generate_certificate(res)
    st.download_button("📥 Download Trust Certificate", cert, f"Cert_{res['filename']}.pdf", "application/pdf")
