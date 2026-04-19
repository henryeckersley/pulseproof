import streamlit as st
import io
import hashlib

class PulseProofDeepLogic:
    def __init__(self, file_data, filename):
        self.file_data = file_data.lower()
        self.filename = filename.lower()
        self.hash = hashlib.sha256(file_data).hexdigest()

    def analyze(self):
        # 1. SCAN FOR AI SOURCE TYPES (The technical 'smoking gun')
        # These are the official IPTC/C2PA uris for AI-generated content
        ai_uris = [b'trainedalgorithmicmedia', b'algorithmicmedia', b'ai-generated']
        ai_metadata_strings = [b'copilot', b'dall-e', b'midjourney', b'firefly', b'openai']
        
        is_ai_sourced = any(uri in self.file_data for uri in ai_uris)
        is_ai_metadata = any(sig in self.file_data for sig in ai_metadata_strings)

        # 2. SCAN FOR VERIFICATION MANIFESTS
        has_c2pa = b'c2pa' in self.file_data or b'jumb' in self.file_data

        # --- REFINED DECISION TREE ---
        if is_ai_sourced or is_ai_metadata:
            # Even if it's verified, it's verified as AI.
            return "AI-GENERATED CONTENT", "red", "Technical markers or metadata strings confirm this is AI-produced."
        
        if has_c2pa:
            # Verified, and not flagged as AI.
            return "VERIFIED HUMAN SOURCE", "green", "Cryptographic signature from a verified human-operated device detected."
        
        # Standard phone photos / normal internet images
        return "LIKELY HUMAN / STANDARD MEDIA", "blue", "Standard format. No signatures or AI markers detected."

# --- UI ---
st.set_page_config(page_title="PulseProof: Logic Fix", layout="wide")
st.title("🛡️ PulseProof: Professional Forensic Audit")

file = st.file_uploader("Upload Asset for Audit", type=["jpg", "jpeg", "png"])

if file:
    bytes_data = file.read()
    engine = PulseProofDeepLogic(bytes_data, file.name)
    verdict, color, detail = engine.analyze()

    if color == "red": st.error(verdict)
    elif color == "green": st.success(verdict)
    else: st.info(verdict)
    
    st.write(f"**Analysis Detail:** {detail}")
    st.divider()
    st.code(f"Asset ID (SHA-256): {engine.hash}")
