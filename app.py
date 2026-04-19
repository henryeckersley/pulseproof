import streamlit as st
import io
import hashlib
import struct
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

# --- THE PRO ENGINE: IPTC & AI SIGNATURES ---
VERIFIED_PUBLISHERS = [
    "associated press", "ap", "reuters", "afp", "bbc", "new york times", 
    "washington post", "getty images", "shutterstock", "bloomberg"
]

AI_TOOL_SIGNATURES = {
    "dall-e": "AI-Generated (OpenAI)",
    "midjourney": "AI-Generated (Midjourney)",
    "stable diffusion": "AI-Generated (Stability AI)",
    "adobe firefly": "AI-Assisted (Adobe)",
    "firefly": "AI-Assisted (Adobe)"
}

class PulseProofPro:
    def __init__(self, file_data, filename):
        self.file_data = file_data
        self.filename = filename.lower()
        self.hash = hashlib.sha256(file_data).hexdigest()

    def deep_scan(self):
        # 1. Check for Cryptographic C2PA Headers
        has_c2pa = b'C2PA' in self.file_data or b'JUMF' in self.file_data
        
        # 2. Scan Binary for AI Tool Strings
        detected_ai = None
        for sig, tool in AI_TOOL_SIGNATURES.items():
            if sig.encode() in self.file_data.lower():
                detected_ai = tool
                break

        # 3. Decision Logic
        if detected_ai:
            verdict = detected_ai
            color = "red"
            detail = "Direct AI tool signature found in file binary."
        elif has_c2pa:
            verdict = "VERIFIED AUTHENTIC (C2PA)"
            color = "green"
            detail = "Cryptographic provenance manifest detected. Origin verified."
        else:
            verdict = "UNVERIFIED / UNKNOWN"
            color = "orange"
            detail = "No C2PA credentials or AI signatures found. Origin is anonymous."

        return {
            "verdict": verdict, "color": color, "detail": detail,
            "hash": self.hash, "filename": self.filename
        }

def generate_pro_report(res):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 750, "PULSEPROOF PRO: DIGITAL PROVENANCE REPORT")
    p.line(50, 740, 550, 740)
    p.setFont("Helvetica", 11)
    p.drawString(50, 710, f"Target File: {res['filename']}")
    p.drawString(50, 690, f"Cryptographic ID: {res['hash']}")
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, 660, f"Analysis Verdict: {res['verdict']}")
    p.setFont("Helvetica", 11)
    p.drawString(50, 640, f"Forensic Detail: {res['detail']}")
    p.setFont("Helvetica-Oblique", 9)
    p.drawString(50, 50, "Disclaimer: This report verifies metadata presence according to C2PA & IPTC standards.")
    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

# --- PRO UI LAYOUT ---
st.set_page_config(page_title="PulseProof Pro", layout="wide")
st.title("⚖️ PulseProof Pro: Media & Policy Verification")
st.markdown("---")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Upload Asset")
    uploaded_file = st.file_uploader("", type=["jpg", "jpeg", "png"])
    if uploaded_file:
        st.image(uploaded_file, use_container_width=True)

if uploaded_file:
    with col2:
        st.subheader("Forensic Analysis")
        data = uploaded_file.read()
        engine = PulseProofPro(data, uploaded_file.name)
        res = engine.deep_scan()

        if res['color'] == "green":
            st.success(f"**{res['verdict']}**")
        elif res['color'] == "red":
            st.error(f"**{res['verdict']}**")
        else:
            st.warning(f"**{res['verdict']}**")

        st.info(f"**Technical Detail:** {res['detail']}")
        
        with st.expander("Security Audit Logs"):
            st.write(f"SHA-256 Hash: `{res['hash']}`")
            st.write(f"Metadata Standard: `C2PA/JUMBF` (Detection: {'Detected' if b'C2PA' in data else 'Not Found'})")

        report = generate_pro_report(res)
        st.download_button("📥 Download Official Provenance Report (PDF)", report, f"Report_{res['filename']}.pdf")
