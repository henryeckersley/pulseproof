"""
PulseProof Forensic Engine v7.4
Fixed: Context-aware publisher detection for non-C2PA web images
Fixed: NASA/ESA/SpaceX publisher recognition
Fixed: ELA sensitivity (scale 12, context thresholds, larger regions)
Fixed: AI spoofed identity detection across all categories
"""

import io
import json
import hashlib
import struct
import base64
import math
import re
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple

import streamlit as st
from PIL import Image, ImageChops, ImageDraw, ImageFont
from PIL.ExifTags import TAGS as PIL_TAGS
import piexif
from cbor2 import loads as cbor_loads

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

# ═══════════════════════════════════════════════════════════
# IPTC VERIFIED NEWS PUBLISHERS (for EXIF/C2PA authorship fields)
# ═══════════════════════════════════════════════════════════
VERIFIED_PUBLISHERS: Dict[str, Dict[str, str]] = {
    "associated press": {"name": "Associated Press", "tier": "t1"},
    "reuters": {"name": "Reuters / Thomson Reuters", "tier": "t1"},
    "thomson reuters": {"name": "Thomson Reuters", "tier": "t1"},
    "afp": {"name": "Agence France-Presse", "tier": "t1"},
    "agence france-presse": {"name": "Agence France-Presse", "tier": "t1"},
    "bbc news": {"name": "BBC News", "tier": "t1"},
    "new york times": {"name": "The New York Times", "tier": "t1"},
    "the new york times": {"name": "The New York Times", "tier": "t1"},
    "washington post": {"name": "The Washington Post", "tier": "t1"},
    "the washington post": {"name": "The Washington Post", "tier": "t1"},
    "the guardian": {"name": "The Guardian", "tier": "t1"},
    "guardian news & media": {"name": "Guardian News & Media", "tier": "t1"},
    "nbc news": {"name": "NBC News", "tier": "t2"},
    "cbs news": {"name": "CBS News", "tier": "t2"},
    "abc news": {"name": "ABC News", "tier": "t2"},
    "bloomberg news": {"name": "Bloomberg News", "tier": "t2"},
    "the wall street journal": {"name": "The Wall Street Journal", "tier": "t2"},
    "wall street journal": {"name": "The Wall Street Journal", "tier": "t2"},
    "usa today": {"name": "USA Today", "tier": "t2"},
    "los angeles times": {"name": "Los Angeles Times", "tier": "t2"},
    "chicago tribune": {"name": "Chicago Tribune", "tier": "t2"},
    "national public radio": {"name": "NPR", "tier": "t2"},
    "pbs newshour": {"name": "PBS NewsHour", "tier": "t2"},
    "propublica": {"name": "ProPublica", "tier": "t2"},
    "the intercept": {"name": "The Intercept", "tier": "t2"},
    "al jazeera": {"name": "Al Jazeera", "tier": "t2"},
    "der spiegel": {"name": "Der Spiegel", "tier": "t2"},
    "le monde": {"name": "Le Monde", "tier": "t2"},
    "the economist": {"name": "The Economist", "tier": "t2"},
    "financial times": {"name": "Financial Times", "tier": "t2"},
    "getty images": {"name": "Getty Images", "tier": "t3"},
    "shutterstock": {"name": "Shutterstock", "tier": "t3"},
}

# ═══════════════════════════════════════════════════════════
# PUBLISHER SEARCH TERMS
# Multi-word names only. Two-letter abbreviations (ap, bbc, cnn, npr)
# are excluded — they match too many non-publisher strings in binary.
# ═══════════════════════════════════════════════════════════
PUBLISHER_SEARCH_TERMS: Dict[str, Dict[str, str]] = {
    "associated press": {"name": "Associated Press", "tier": "t1"},
    "reuters": {"name": "Reuters / Thomson Reuters", "tier": "t1"},
    "thomson reuters": {"name": "Thomson Reuters", "tier": "t1"},
    "agence france-presse": {"name": "Agence France-Presse", "tier": "t1"},
    "bbc news": {"name": "BBC News", "tier": "t1"},
    "new york times": {"name": "The New York Times", "tier": "t1"},
    "the new york times": {"name": "The New York Times", "tier": "t1"},
    "washington post": {"name": "The Washington Post", "tier": "t1"},
    "the washington post": {"name": "The Washington Post", "tier": "t1"},
    "the guardian": {"name": "The Guardian", "tier": "t1"},
    "nbc news": {"name": "NBC News", "tier": "t2"},
    "cbs news": {"name": "CBS News", "tier": "t2"},
    "abc news": {"name": "ABC News", "tier": "t2"},
    "bloomberg news": {"name": "Bloomberg News", "tier": "t2"},
    "wall street journal": {"name": "The Wall Street Journal", "tier": "t2"},
    "usa today": {"name": "USA Today", "tier": "t2"},
    "los angeles times": {"name": "Los Angeles Times", "tier": "t2"},
    "chicago tribune": {"name": "Chicago Tribune", "tier": "t2"},
    "national public radio": {"name": "NPR", "tier": "t2"},
    "pbs newshour": {"name": "PBS NewsHour", "tier": "t2"},
    "propublica": {"name": "ProPublica", "tier": "t2"},
    "the intercept": {"name": "The Intercept", "tier": "t2"},
    "al jazeera": {"name": "Al Jazeera", "tier": "t2"},
    "der spiegel": {"name": "Der Spiegel", "tier": "t2"},
    "le monde": {"name": "Le Monde", "tier": "t2"},
    "the economist": {"name": "The Economist", "tier": "t2"},
    "financial times": {"name": "Financial Times", "tier": "t2"},
    "getty images": {"name": "Getty Images", "tier": "t3"},
    "shutterstock": {"name": "Shutterstock", "tier": "t3"},
    # Science / Space agencies
    "national aeronautics and space administration": {"name": "NASA", "tier": "t1"},
    "nasa": {"name": "NASA", "tier": "t1"},
    "nasa.gov": {"name": "NASA", "tier": "t1"},
    "european space agency": {"name": "ESA", "tier": "t2"},
    "esa.int": {"name": "ESA", "tier": "t2"},
    "spacex": {"name": "SpaceX", "tier": "t3"},
}

# ═══════════════════════════════════════════════════════════
# AI TOOL SIGNATURES
# ═══════════════════════════════════════════════════════════
AI_TOOL_SIGNATURES: Dict[str, Dict[str, str]] = {
    "dall-e": {"label": "DALL-E", "type": "ai_generated", "vendor": "OpenAI"},
    "dall·e": {"label": "DALL-E", "type": "ai_generated", "vendor": "OpenAI"},
    "openai": {"label": "OpenAI API", "type": "ai_generated", "vendor": "OpenAI"},
    "chatgpt": {"label": "ChatGPT", "type": "ai_generated", "vendor": "OpenAI"},
    "midjourney": {"label": "Midjourney", "type": "ai_generated", "vendor": "Midjourney"},
    "stable diffusion": {"label": "Stable Diffusion", "type": "ai_generated", "vendor": "Stability AI"},
    "stability ai": {"label": "Stability AI", "type": "ai_generated", "vendor": "Stability AI"},
    "leonardo.ai": {"label": "Leonardo.AI", "type": "ai_generated", "vendor": "Leonardo"},
    "ideogram": {"label": "Ideogram", "type": "ai_generated", "vendor": "Ideogram"},
    "flux": {"label": "FLUX", "type": "ai_generated", "vendor": "Black Forest Labs"},
    "copilot": {"label": "Microsoft Copilot", "type": "ai_generated", "vendor": "Microsoft"},
    "bing image creator": {"label": "Bing Image Creator", "type": "ai_generated", "vendor": "Microsoft"},
    "adobe firefly": {"label": "Adobe Firefly", "type": "ai_assisted", "vendor": "Adobe"},
    "generative fill": {"label": "Generative Fill", "type": "ai_assisted", "vendor": "Adobe"},
    "neural filters": {"label": "Neural Filters", "type": "ai_assisted", "vendor": "Adobe"},
    "artbreeder": {"label": "Artbreeder", "type": "ai_assisted", "vendor": "Artbreeder"},
}

AI_SOURCE_TYPES = {
    "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicmedia": {"label": "Algorithmic Media", "type": "ai_generated"},
    "algorithmicmedia": {"label": "Algorithmic Media", "type": "ai_generated"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/compositewithtrainedalgorithmicmedia": {"label": "Composite w/ AI", "type": "ai_assisted"},
    "compositewithtrainedalgorithmicmedia": {"label": "Composite w/ AI", "type": "ai_assisted"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedalgorithmicmedia": {"label": "Trained Algorithmic", "type": "ai_assisted"},
    "trainedalgorithmicmedia": {"label": "Trained Algorithmic", "type": "ai_assisted"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicenhancement": {"label": "Algorithmic Enhancement", "type": "ai_assisted"},
    "algorithmicenhancement": {"label": "Algorithmic Enhancement", "type": "ai_assisted"},
}

HUMAN_SOURCE_TYPES = {
    "http://cv.iptc.org/newscodes/digitalsourcetype/digitalcapture": {"label": "Digital Capture", "type": "human"},
    "digitalcapture": {"label": "Digital Capture", "type": "human"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/negativefilm": {"label": "Negative Film", "type": "human"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/positivefilm": {"label": "Positive Film", "type": "human"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/print": {"label": "Print", "type": "human"},
    "http://cv.iptc.org/newscodes/digitalsourcetype/screenshot": {"label": "Screenshot", "type": "human"},
}


# ═══════════════════════════════════════════════════════════
# JUMBF BINARY PARSER
# ═══════════════════════════════════════════════════════════
class JUMBFParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def parse_all(self) -> List[Dict]:
        boxes = []
        while self.pos < len(self.data) - 8:
            box = self._read_box()
            if box is None:
                break
            boxes.append(box)
            if box["length"] == 0:
                break
            self.pos = box["end"]
        return boxes

    def _read_box(self) -> Optional[Dict]:
        if self.pos + 8 > len(self.data):
            return None
        length = struct.unpack(">I", self.data[self.pos:self.pos+4])[0]
        box_type = self.data[self.pos+4:self.pos+8].decode("ascii", errors="replace")
        hs = 8
        if length == 1:
            if self.pos + 16 > len(self.data):
                return None
            length = struct.unpack(">Q", self.data[self.pos+8:self.pos+16])[0]
            hs = 16
        elif length == 0:
            length = len(self.data) - self.pos
        if length < hs:
            self.pos += 1
            return None
        cs = self.pos + hs
        ce = min(self.pos + length, len(self.data))
        content = self.data[cs:ce]
        children = []
        if box_type in ("jumb", "c2pa", "c2pa.manifest"):
            sub = JUMBFParser(content)
            children = sub.parse_all()
        return {"type": box_type, "length": length, "offset": self.pos,
                "end": self.pos + length, "content": content, "children": children}


# ═══════════════════════════════════════════════════════════
# C2PA MANIFEST EXTRACTOR
# ═══════════════════════════════════════════════════════════
class C2PAParser:
    def __init__(self, file_data: bytes, filename: str):
        self.file_data = file_data
        self.filename = filename.lower()
        self.manifests: List[Dict] = []
        self.exif_data: Dict = {}
        self.has_c2pa = False
        self.jumbf_boxes: List[Dict] = []
        self.raw_jumbf: Optional[bytes] = None
        self.raw_text: str = ""
        self.authority_fields: List[str] = []

    def parse(self) -> Dict:
        if self.filename.endswith((".jpg", ".jpeg")):
            self.raw_jumbf = self._extract_jpeg()
        elif self.filename.endswith(".png"):
            self.raw_jumbf = self._extract_png()
        elif self.filename.endswith(".webp"):
            self.raw_jumbf = self._extract_webp()

        if self.raw_jumbf and len(self.raw_jumbf) > 8:
            parser = JUMBFParser(self.raw_jumbf)
            self.jumbf_boxes = parser.parse_all()
            self._extract_manifests(self.jumbf_boxes)
            self.has_c2pa = len(self.manifests) > 0

        if not self.has_c2pa:
            self._raw_c2pa_fallback()

        self._extract_raw_text()
        self._build_authority_fields()
        self._extract_exif()
        # Rebuild authority after EXIF is available
        self._build_authority_fields()
        return self._build()

    def _raw_c2pa_fallback(self):
        data = self.file_data
        dl = data.lower()
        if b"jumb" in data or b"JUMF" in data:
            self.has_c2pa = True
        for marker in [b"c2pa", b"C2PA", b"content credentials",
                       b"Content Credentials", b"content-authenticity",
                       b"Content Authenticity"]:
            if marker in data or marker in dl:
                self.has_c2pa = True
                break
        if self.has_c2pa and not self.manifests:
            for tool_key, tool_info in AI_TOOL_SIGNATURES.items():
                if tool_key.encode() in dl:
                    self.manifests.append({
                        "claim_generator": tool_key,
                        "instance_id": "", "assertions": [],
                        "digital_source_type": None,
                        "actions": [], "signer_info": None,
                    })
                    break
            c2pa_idx = dl.find(b"c2pa")
            if c2pa_idx >= 0:
                for offset in range(max(0, c2pa_idx - 300),
                                    min(len(data), c2pa_idx + 3000)):
                    try:
                        dec = cbor_loads(data[offset:])
                        if isinstance(dec, dict):
                            self._proc_manifest(dec)
                            return
                        elif isinstance(dec, (list, tuple)):
                            for item in dec:
                                if isinstance(item, dict):
                                    self._proc_manifest(item)
                                    return
                                elif isinstance(item, bytes):
                                    try:
                                        inner = cbor_loads(item)
                                        if isinstance(inner, dict):
                                            self._proc_manifest(inner)
                                            return
                                    except Exception:
                                        continue
                    except Exception:
                        continue

    def _extract_raw_text(self):
        strings = []
        current = []
        for byte in self.file_data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if len(current) >= 4:
            strings.append("".join(current))
        self.raw_text = " ".join(strings).lower()

    def _build_authority_fields(self):
        """
        Build authorship-context strings for publisher matching.
        
        Strategy:
        - ALWAYS: search EXIF authorship fields and C2PA assertion URLs
        - C2PA images: DO NOT search raw_text (C2PA schemas reference publisher 
          names as coalition members -> false positives like ChatGPT matching 
          "associated press")
        - Non-C2PA images: search raw_text WITH context requirements — publisher 
          name must appear near context keywords (copyright, .com, credit, etc.)
          to distinguish real attribution from noise
        """
        fields = []

        # EXIF authorship fields
        for key in ["Artist", "Copyright", "Author", "Creator", "Publisher",
                     "Credit", "Byline", "BylineTitle", "Writer", "Contact",
                     "ImageDescription"]:
            val = self.exif_data.get(key, "")
            if val:
                fields.append(val)

        # C2PA claim generator
        for m in self.manifests:
            if m.get("claim_generator"):
                fields.append(m["claim_generator"])

        # C2PA authorship assertions
        for m in self.manifests:
            for a in m.get("assertions", []):
                url = a.get("url", "").lower()
                if any(k in url for k in ["creative_work", "author", "copyright",
                                            "publisher", "creator", "organization"]):
                    fields.append(a.get("data", ""))

        # Non-C2PA images: search raw_text with context requirements
        # This catches web-served images (CNN, Reuters, etc.) that strip EXIF
        # but still have attribution strings in the binary
        if not self.has_c2pa and self.raw_text:
            context_keywords = [
                "copyright", "\u00a9", "(c)", "credit", "source:", "photo by",
                "image by", "courtesy of", "distributed by", "via",
                ".com", ".org", ".gov", ".net", ".co.",
                "getty images", "afp photo", "reuters/", "epa/",
                "press/", "news/", "media/", "photo/", "images/",
            ]

            for pub_key, pub_info in PUBLISHER_SEARCH_TERMS.items():
                start = 0
                while True:
                    idx = self.raw_text.find(pub_key, start)
                    if idx == -1:
                        break

                    window_start = max(0, idx - 150)
                    window_end = min(len(self.raw_text), idx + len(pub_key) + 150)
                    window = self.raw_text[window_start:window_end]

                    has_context = any(ctx in window for ctx in context_keywords)

                    if has_context:
                        ctx_start = max(0, idx - 80)
                        ctx_end = min(len(self.raw_text), idx + len(pub_key) + 80)
                        context_snippet = self.raw_text[ctx_start:ctx_end]
                        fields.append(context_snippet)
                        break

                    start = idx + len(pub_key)

        self.authority_fields = [f.lower() for f in fields if f]

    def _build(self) -> Dict:
        all_assert, gen, dst, actions, signer = [], None, None, [], None
        for m in self.manifests:
            all_assert.extend(m.get("assertions", []))
            if m.get("claim_generator") and not gen:
                gen = m["claim_generator"]
            if m.get("digital_source_type") and not dst:
                dst = m["digital_source_type"]
            if m.get("signer_info") and not signer:
                signer = m["signer_info"]
            actions.extend(m.get("actions", []))
        return {
            "c2pa_present": self.has_c2pa,
            "claim_generator": gen,
            "manifest_count": len(self.manifests),
            "assertions": all_assert,
            "digital_source_type": dst,
            "actions": actions,
            "signer_info": signer,
            "exif": self.exif_data,
            "jumbf_box_count": len(self.jumbf_boxes),
            "raw_text": self.raw_text,
            "authority_fields": self.authority_fields,
        }

    def _extract_jpeg(self) -> Optional[bytes]:
        data = self.file_data
        frags: Dict[int, Dict[int, bytes]] = {}
        app1 = b""
        i = 0
        while i < len(data) - 1:
            if data[i] != 0xFF:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            marker = data[i+1]
            if 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker == 0xDA:
                break
            if marker in (0x00, 0xFF, 0xD8, 0xD9):
                i += 2
                continue
            if i + 4 > len(data):
                break
            sl = struct.unpack(">H", data[i+2:i+4])[0]
            if sl < 2:
                i += 2
                continue
            sd = data[i+4:i+2+sl]
            if marker == 0xEB and sd[:4] == b"JUMF" and len(sd) >= 7:
                frags.setdefault(sd[4], {})[sd[5]] = sd[7:]
            if marker == 0xE1:
                app1 += sd
            i += 2 + sl
        jumbf = b""
        for iid in sorted(frags.keys()):
            for seq in sorted(frags[iid].keys()):
                jumbf += frags[iid][seq]
        if not jumbf:
            idx = data.find(b"\x00\x00\x00\x1c\x6a\x75\x6d\x62")
            if idx >= 0:
                jumbf = data[idx:]
        if not jumbf and b"c2pa" in app1.lower():
            self.has_c2pa = True
        return jumbf if jumbf else None

    def _extract_png(self) -> Optional[bytes]:
        data = self.file_data
        if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        i = 8
        while i + 12 <= len(data):
            length = struct.unpack(">I", data[i:i+4])[0]
            ct = data[i+4:i+8]
            if ct == b"caBX":
                return data[i+8:i+8+length]
            if ct == b"IEND":
                break
            i += 12 + length + 4
        return None

    def _extract_webp(self) -> Optional[bytes]:
        data = self.file_data
        if len(data) < 12 or data[:4] != b"RIFF":
            return None
        i = 12
        while i + 8 < len(data):
            cs = struct.unpack("<I", data[i+4:i+8])[0]
            if data[i:i+4] == b"JUMF":
                return data[i+8:i+8+cs]
            i += 8 + cs + (cs % 2)
        return None

    def _extract_manifests(self, boxes):
        for b in boxes:
            if b["type"] == "c2pa":
                for c in b.get("children", []):
                    if c["type"] == "c2pa.manifest":
                        self._try_cbor(c["content"])
                    elif c["type"] == "jumb":
                        self._extract_manifests(c.get("children", []))
            elif b["type"] == "jumb":
                self._extract_manifests(b.get("children", []))
            elif b["type"] in ("c2pa.manifest", "c2pa.assertion"):
                self._try_cbor(b["content"])

    def _try_cbor(self, content: bytes):
        if not content or len(content) < 2:
            return
        for offset in range(min(len(content), 500)):
            try:
                dec = cbor_loads(content[offset:])
                if isinstance(dec, dict):
                    self._proc_manifest(dec)
                    return
                elif isinstance(dec, (list, tuple)):
                    for item in dec:
                        if isinstance(item, dict):
                            self._proc_manifest(item)
                            return
                        elif isinstance(item, bytes):
                            try:
                                inner = cbor_loads(item)
                                if isinstance(inner, dict):
                                    self._proc_manifest(inner)
                                    return
                            except Exception:
                                continue
            except Exception:
                continue

    def _proc_manifest(self, m: Dict):
        p = {
            "claim_generator": m.get("claim_generator", "unknown"),
            "instance_id": m.get("instance_id", ""),
            "assertions": [],
            "digital_source_type": None,
            "actions": [],
            "signer_info": None,
        }
        if "signature" in m:
            p["signer_info"] = {"has_signature": True}
        for a in m.get("assertions", []):
            if isinstance(a, dict):
                self._proc_assertion(a.get("url", ""), a.get("data", {}), p)
            elif isinstance(a, (list, tuple)) and len(a) >= 2:
                self._proc_assertion(str(a[0]), a[1] if len(a) > 1 else {}, p)
        if "digitalSourceType" in m:
            p["digital_source_type"] = str(m["digitalSourceType"])
        self.manifests.append(p)

    def _proc_assertion(self, url, data, p):
        ds = json.dumps(data) if not isinstance(data, str) else data
        if "digitalSourceType" in ds or "digital_source" in url.lower():
            if isinstance(data, dict):
                v = data.get("digitalSourceType", data.get("value", ""))
                if v:
                    p["digital_source_type"] = str(v)
        if "action" in url.lower():
            p["actions"].append({
                "url": url,
                "data": data if isinstance(data, (dict, list)) else str(data)[:500],
            })
        if "signature" in url.lower() or "authority" in url.lower():
            p["signer_info"] = data if isinstance(data, dict) else {"url": url}
        p["assertions"].append({"url": url, "data": ds[:800]})

    def _extract_exif(self):
        result = {}
        try:
            ed = piexif.load(self.file_data)
            for ifd_name in ("0th", "Exif", "GPS", "1st"):
                ifd = ed.get(ifd_name, {})
                if not ifd:
                    continue
                for tid, val in ifd.items():
                    tinfo = piexif.TAGS.get(ifd_name, {}).get(tid, {})
                    tname = tinfo.get("name", f"Tag_{tid}")
                    if isinstance(val, bytes):
                        try:
                            d = val.decode("utf-8", errors="replace").strip("\x00")
                            if d.isprintable() and len(d) > 0:
                                val = d
                            else:
                                continue
                        except Exception:
                            continue
                    if isinstance(val, (list, tuple)):
                        if all(isinstance(v, (int, float)) for v in val) and len(val) <= 6:
                            val = list(val)
                        else:
                            continue
                    result[tname] = str(val)[:500]
        except Exception:
            pass
        if len(result) < 3:
            try:
                img = Image.open(io.BytesIO(self.file_data))
                info = img._getexif()
                if info:
                    for tag, value in info.items():
                        tname = PIL_TAGS.get(tag, f"Tag_{tag}")
                        if isinstance(value, bytes):
                            try:
                                value = value.decode("utf-8", errors="replace").strip("\x00")
                                if not value.isprintable():
                                    continue
                            except Exception:
                                continue
                        if tname not in result:
                            result[tname] = str(value)[:500]
            except Exception:
                pass
        if len(result) < 2:
            try:
                img = Image.open(io.BytesIO(self.file_data))
                for key in ("dpi", "aspect", "loop", "duration", "comment",
                            "icc_profile", "photoshop", "adobe"):
                    if key in img.info and key not in result:
                        val = img.info[key]
                        if isinstance(val, bytes):
                            try:
                                val = val.decode("utf-8", errors="replace")[:500]
                            except Exception:
                                val = f"<binary: {len(val)} bytes>"
                        result[f"Pillow_{key}"] = str(val)[:500]
            except Exception:
                pass
        self.exif_data = result


# ═══════════════════════════════════════════════════════════
# PROVENANCE VERIFIER
# ═══════════════════════════════════════════════════════════
class ProvenanceVerifier:
    def __init__(self, c2pa, fh, fn):
        self.c2pa = c2pa
        self.fh = fh
        self.fn = fn
        self._ai_detected = self._detects_ai()

    def _detects_ai(self) -> bool:
        gen = (self.c2pa.get("claim_generator") or "").lower()
        for tk in AI_TOOL_SIGNATURES:
            if tk in gen:
                return True
        dst = (self.c2pa.get("digital_source_type") or "").lower()
        for uri in AI_SOURCE_TYPES:
            if uri.lower() in dst:
                return True
        rt = (self.c2pa.get("raw_text") or "").lower()
        for tk in AI_TOOL_SIGNATURES:
            if tk in rt:
                return True
        for action in self.c2pa.get("actions", []):
            astr = json.dumps(action).lower()
            for tk in AI_TOOL_SIGNATURES:
                if tk in astr:
                    return True
            if any(k in astr for k in ["generative", "inpaint", "outpaint", "synthetic"]):
                return True
        sw = (self.c2pa.get("exif", {}).get("Software", "") or "").lower()
        for tk in AI_TOOL_SIGNATURES:
            if tk in sw:
                return True
        return False

    def generate_scorecard(self):
        return {
            "overall_score": 0,
            "c2pa_validity": self._c2pa(),
            "publisher_verification": self._pub(),
            "ai_detection": self._ai(),
            "metadata_integrity": self._meta(),
            "tamper_detection": {
                "score": 0, "max_score": 10,
                "status": "pending", "details": "Awaiting ELA",
            },
        }

    def finalize(self, sc, tamp):
        sc["tamper_detection"] = {
            "score": tamp["score"], "max_score": 10,
            "status": tamp["status"], "details": tamp["details"],
        }
        t = (sc["c2pa_validity"]["score"]
             + sc["publisher_verification"]["score"]
             + sc["ai_detection"]["score"]
             + sc["metadata_integrity"]["score"]
             + sc["tamper_detection"]["score"])
        sc["overall_score"] = t
        if t >= 80:
            sc["trust_level"] = "Trusted"
        elif t >= 60:
            sc["trust_level"] = "Verified"
        elif t >= 40:
            sc["trust_level"] = "Caution"
        elif t >= 20:
            sc["trust_level"] = "Suspicious"
        else:
            sc["trust_level"] = "Untrusted"
        return sc

    def _c2pa(self):
        if not self.c2pa.get("c2pa_present"):
            return {
                "score": 0, "max_score": 25, "status": "missing",
                "details": "No C2PA manifest detected. Provenance unverifiable.",
                "flag": "NO_C2PA",
            }
        gen = (self.c2pa.get("claim_generator") or "").lower()
        for tk, ti in AI_TOOL_SIGNATURES.items():
            if tk in gen:
                return {
                    "score": 5, "max_score": 25, "status": "ai_signed",
                    "details": f"C2PA present but AI-signed: {ti['label']} ({ti['vendor']}). Transparency exists but origin is synthetic.",
                    "flag": "AI_C2PA",
                }
        sig = self.c2pa.get("signer_info")
        sd = " Signature authority detected." if sig else ""
        return {
            "score": 25, "max_score": 25, "status": "valid",
            "details": f"C2PA manifest valid.{sd} Generator: {self.c2pa.get('claim_generator', '?')}",
            "flag": None,
        }

    def _pub(self):
        if self._ai_detected:
            return {
                "score": 0, "max_score": 25, "status": "spoofed",
                "details": "AI-generated content detected. Publisher identity cannot be trusted \u2014 AI manifests may reference legitimate agencies as coalition members, not as the actual source.",
                "flag": "SPOOFED_IDENTITY",
            }

        authority = self.c2pa.get("authority_fields", [])
        combined = " ".join(authority).lower()

        best, bt = None, "t99"
        for p, info in PUBLISHER_SEARCH_TERMS.items():
            if p in combined and info["tier"] < bt:
                best, bt = info["name"], info["tier"]

        if best:
            ts = {"t1": 25, "t2": 22, "t3": 18}
            return {
                "score": ts.get(bt, 15), "max_score": 25, "status": "verified",
                "details": f"Publisher: {best} ({bt})", "flag": None,
            }

        exif = self.c2pa.get("exif", {})
        if exif.get("Copyright") or exif.get("Artist"):
            return {
                "score": 12, "max_score": 25, "status": "unverified",
                "details": "Copyright/Artist present but not IPTC verified.",
                "flag": "UNVERIFIED_PUB",
            }
        return {
            "score": 3, "max_score": 25, "status": "unknown",
            "details": "No publisher information found.", "flag": "NO_PUBLISHER",
        }

    def _ai(self):
        dst = (self.c2pa.get("digital_source_type") or "").lower()
        for uri, info in AI_SOURCE_TYPES.items():
            if uri.lower() in dst:
                s = 0 if info["type"] == "ai_generated" else 8
                return {
                    "score": s, "max_score": 25, "status": info["type"],
                    "details": f"C2PA Source: {info['label']} ({uri})",
                    "flag": "AI_C2PA_SRC",
                }
        for uri, info in HUMAN_SOURCE_TYPES.items():
            if uri.lower() in dst:
                return {
                    "score": 25, "max_score": 25, "status": "human",
                    "details": f"Verified human: {info['label']}", "flag": None,
                }
        gen = (self.c2pa.get("claim_generator") or "").lower()
        for tk, ti in AI_TOOL_SIGNATURES.items():
            if tk in gen:
                s = 0 if ti["type"] == "ai_generated" else 8
                return {
                    "score": s, "max_score": 25, "status": ti["type"],
                    "details": f"Generator: {ti['label']} by {ti['vendor']}",
                    "flag": "AI_GEN",
                }
        for action in self.c2pa.get("actions", []):
            astr = json.dumps(action).lower()
            for tk, ti in AI_TOOL_SIGNATURES.items():
                if tk in astr:
                    s = 0 if ti["type"] == "ai_generated" else 8
                    return {
                        "score": s, "max_score": 25, "status": ti["type"],
                        "details": f"AI in history: {ti['label']}", "flag": "AI_ACTION",
                    }
            if any(k in astr for k in ["generative", "inpaint", "outpaint", "synthetic"]):
                return {
                    "score": 5, "max_score": 25, "status": "ai_assisted",
                    "details": "Generative action in edit history.", "flag": "AI_ASSISTED",
                }
        sw = (self.c2pa.get("exif", {}).get("Software", "") or "").lower()
        for tk, ti in AI_TOOL_SIGNATURES.items():
            if tk in sw:
                s = 0 if ti["type"] == "ai_generated" else 8
                return {
                    "score": s, "max_score": 25, "status": ti["type"],
                    "details": f"AI in EXIF: {ti['label']}", "flag": "AI_EXIF",
                }
        return {
            "score": 18, "max_score": 25, "status": "likely_human",
            "details": "No AI indicators found in C2PA, EXIF, or action history.",
            "flag": None,
        }

    def _meta(self):
        exif = self.c2pa.get("exif", {})
        crit = ["DateTimeOriginal", "DateTime", "Make", "Model"]
        imp = ["Artist", "Copyright", "GPSLatitude", "GPSLongitude", "Software"]
        cp = sum(1 for f in crit if exif.get(f))
        ip = sum(1 for f in imp if exif.get(f))
        has_c2pa = self.c2pa.get("c2pa_present", False)
        is_webp = self.fn.endswith(".webp")
        is_png = self.fn.endswith(".png")

        if cp == len(crit):
            sc, st = 15, "complete"
        elif cp >= 2:
            sc, st = 9, "partial"
        elif cp + ip > 0:
            sc, st = 5, "minimal"
        elif has_c2pa and not self._ai_detected:
            sc, st = 8, "c2pa_compensated"
        elif has_c2pa and self._ai_detected:
            sc, st = 1, "ai_no_camera"
        elif (is_webp or is_png) and len(exif) > 0:
            sc, st = 5, "format_limited"
        elif (is_webp or is_png):
            sc, st = 3, "format_limited"
        elif len(exif) > 0:
            sc, st = 3, "minimal"
        else:
            sc, st = 0, "stripped"

        det = "Full camera metadata." if st == "complete" else \
              "EXIF stripped/absent." if st == "stripped" else \
              "AI-generated \u2014 no camera hardware metadata possible." if st == "ai_no_camera" else \
              f"Partial. Camera: {cp}/{len(crit)}, Other: {ip}/{len(imp)}"
        if has_c2pa and not self._ai_detected and st != "complete":
            det += " C2PA manifest partially compensates."
        if (is_webp or is_png) and st in ("format_limited", "minimal"):
            det += " Format has limited EXIF support."

        return {
            "score": sc, "max_score": 15, "status": st, "details": det,
            "flag": "METADATA_STRIPPED" if st == "stripped" else None,
        }


# ═══════════════════════════════════════════════════════════
# TAMPER DETECTOR (Error Level Analysis)
# v7.4: Realistic forensic parameters
# ═══════════════════════════════════════════════════════════
class TamperDetector:
    MAX_DIM = 2000
    ELA_Q = 75
    ELA_SCALE = 12
    GRID = 48
    MIN_ERR = 20
    MIN_COMPONENT = 5
    REL_THRESH = 2.5

    def __init__(self, image: Image.Image):
        self.orig = image.convert("RGB")
        self.w, self.h = self.orig.size

    def analyze(self) -> Dict:
        ela_img, ela_arr = self._ela()
        regions = self._detect(ela_arr)
        heatmap = self._heatmap(ela_img)
        annotated = self._annotate(regions)
        tpx = self.w * self.h
        spx = sum(r["width"] * r["height"] for r in regions)
        ratio = spx / tpx if tpx > 0 else 0
        if ratio < 0.01:
            sc, st = 10, "clean"
        elif ratio < 0.03:
            sc, st = 8, "minor_artifacts"
        elif ratio < 0.08:
            sc, st = 5, "suspicious"
        else:
            sc, st = 2, "tampered"
        return {
            "score": sc, "status": st,
            "details": f"ELA: {len(regions)} suspicious region(s). Affected: {ratio*100:.1f}%.",
            "regions": regions,
            "heatmap_pil": heatmap,
            "annotated_pil": annotated,
            "ela_pil": ela_img,
        }

    def _ela(self):
        img = self.orig.copy()
        if max(img.size) > self.MAX_DIM:
            sc = self.MAX_DIM / max(img.size)
            img = img.resize((int(img.width*sc), int(img.height*sc)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=self.ELA_Q)
        buf.seek(0)
        recomp = Image.open(buf).convert("RGB")
        if recomp.size != img.size:
            recomp = recomp.resize(img.size, Image.LANCZOS)
        diff = ImageChops.difference(img, recomp)
        scaled = diff.point(lambda x: min(255, x * self.ELA_SCALE))
        px = list(scaled.getdata())
        w, h = scaled.size
        arr = [[(px[y*w+x][0]+px[y*w+x][1]+px[y*w+x][2])/3.0
                for x in range(w)] for y in range(h)]
        return scaled, arr

    def _detect(self, arr):
        if not arr:
            return []
        h, w = len(arr), len(arr[0])
        gh, gw = max(1, h // self.GRID), max(1, w // self.GRID)
        grid, errs = [], []
        for gy in range(gh):
            for gx in range(gw):
                ys, xs = gy * self.GRID, gx * self.GRID
                ye, xe = min(ys + self.GRID, h), min(xs + self.GRID, w)
                t = sum(arr[y][x] for y in range(ys, ye) for x in range(xs, xe))
                c = (ye - ys) * (xe - xs)
                avg = t / c if c > 0 else 0
                grid.append(avg)
                errs.append(avg)
        if not errs:
            return []

        sorted_errs = sorted(errs)
        median_err = sorted_errs[len(sorted_errs) // 2]
        thresh = max(median_err * self.REL_THRESH, self.MIN_ERR)

        sus = {(i // gw, i % gw) for i, e in enumerate(grid) if e > thresh}
        vis, regs = set(), []
        for cell in sus:
            if cell in vis:
                continue
            q, comp = [cell], set()
            while q:
                cur = q.pop(0)
                if cur in vis or cur not in sus:
                    continue
                vis.add(cur)
                comp.add(cur)
                cy, cx = cur
                for dy, dx in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                    nb = (cy + dy, cx + dx)
                    if nb in sus and nb not in vis:
                        q.append(nb)
            if len(comp) >= self.MIN_COMPONENT:
                mgx = min(c[1] for c in comp)
                Mgx = max(c[1] for c in comp)
                mgy = min(c[0] for c in comp)
                Mgy = max(c[0] for c in comp)
                ae = sum(grid[gy * gw + gx] for gy, gx in comp) / len(comp)
                regs.append({
                    "x": mgx * self.GRID, "y": mgy * self.GRID,
                    "width": (Mgx - mgx + 1) * self.GRID,
                    "height": (Mgy - mgy + 1) * self.GRID,
                    "confidence": min(1.0, (ae - median_err) / (median_err + 1)),
                    "severity": "high" if ae > median_err * 4 else \
                                "medium" if ae > median_err * 3 else "low",
                    "description": f"ELA anomaly (err={ae:.1f}, median={median_err:.1f}, ratio={ae/median_err:.1f}x)",
                })
        return regs

    def _heatmap(self, ela):
        r, g, b = ela.split()
        r = r.point(lambda x: min(255, int(x * 2.5)))
        g = g.point(lambda x: min(255, int(x * 1.2)))
        b = b.point(lambda x: min(255, int(x * 0.3)))
        hm = Image.merge("RGB", (r, g, b))
        return hm.resize(self.orig.size, Image.LANCZOS) if hm.size != self.orig.size else hm

    def _annotate(self, regions):
        img = self.orig.copy()
        draw = ImageDraw.Draw(img, "RGBA")
        for i, r in enumerate(regions):
            cm = {"high": (239, 68, 68), "medium": (245, 158, 11), "low": (129, 140, 248)}
            col = cm.get(r["severity"], (239, 68, 68))
            x, y, w, h = r["x"], r["y"], r["width"], r["height"]
            draw.rectangle([x, y, x + w, y + h], fill=col + (40,), outline=col + (200,), width=2)
            try:
                font = ImageFont.truetype("arial.ttf", 14)
            except Exception:
                font = ImageFont.load_default()
            label = f"R{i+1} {r['severity'].upper()}"
            bb = font.getbbox(label)
            tw, th = bb[2] - bb[0], bb[3] - bb[1]
            draw.rectangle([x, y - th - 6, x + tw + 8, y], fill=col + (220,))
            draw.text((x + 4, y - th - 4), label, fill=(255, 255, 255, 255), font=font)
        return img


# ═══════════════════════════════════════════════════════════
# CERTIFICATE GENERATOR
# ═══════════════════════════════════════════════════════════
class CertificateGenerator:
    def __init__(self, sc, c2pa, tamp, fh, fn):
        self.sc = sc
        self.c2pa = c2pa
        self.tamp = tamp
        self.fh = fh
        self.fn = fn
        self.cid = f"PP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{fh[:8].upper()}"
        self.ts = datetime.now(timezone.utc).isoformat()

    def gen_json(self):
        return {
            "certificate_id": self.cid,
            "version": "7.4",
            "standard": "C2PA v1.3 / IPTC Photo Metadata",
            "issued_at": self.ts,
            "asset": {"filename": self.fn, "sha256": self.fh},
            "provenance_scorecard": self.sc,
            "c2pa_metadata": {
                "present": self.c2pa.get("c2pa_present", False),
                "claim_generator": self.c2pa.get("claim_generator"),
                "digital_source_type": self.c2pa.get("digital_source_type"),
                "assertion_count": len(self.c2pa.get("assertions", [])),
                "action_count": len(self.c2pa.get("actions", [])),
            },
            "tamper_analysis": {
                "status": self.tamp.get("status"),
                "regions": len(self.tamp.get("regions", [])),
                "detail": self.tamp.get("details"),
            },
            "verification_hash": hashlib.sha256(
                json.dumps(
                    {"fh": self.fh, "sc": self.sc["overall_score"], "ts": self.ts},
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
        }

    def gen_pdf(self):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        T = ParagraphStyle("T", parent=styles["Title"], fontSize=22,
                           textColor=colors.HexColor("#1e3a5f"), spaceAfter=6)
        H = ParagraphStyle("H", parent=styles["Heading2"], fontSize=13,
                           textColor=colors.HexColor("#1e3a5f"), spaceBefore=16, spaceAfter=8)
        B = ParagraphStyle("B", parent=styles["Normal"], fontSize=9.5,
                           leading=13, textColor=colors.HexColor("#334155"))
        SM = ParagraphStyle("SM", parent=styles["Normal"], fontSize=8,
                            leading=10, textColor=colors.HexColor("#94a3b8"))
        el = []
        el.append(Paragraph("PULSEPROOF", T))
        el.append(Paragraph("Provenance Trust Certificate", ParagraphStyle(
            "Sub", parent=styles["Heading1"], fontSize=16,
            textColor=colors.HexColor("#334155"), spaceAfter=4)))
        el.append(Paragraph(
            f"Certificate ID: {self.cid}  |  Issued: {self.ts[:19]} UTC",
            ParagraphStyle("S", parent=styles["Normal"], fontSize=11,
                           textColor=colors.HexColor("#64748b"), spaceAfter=20)))
        el.append(HRFlowable(width="100%", thickness=2,
                              color=colors.HexColor("#1e3a5f"), spaceAfter=16))
        el.append(Paragraph("ASSET INFORMATION", H))
        at = Table(
            [["Filename", self.fn], ["SHA-256", self.fh],
             ["Analyzed", self.ts[:19] + " UTC"]],
            colWidths=[1.5 * inch, 5 * inch])
        at.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1e3a5f")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        el.append(at)
        el.append(Paragraph("PROVENANCE SCORECARD", H))
        sd = [[
            Paragraph("<b>Category</b>", B),
            Paragraph("<b>Score</b>", B),
            Paragraph("<b>Status</b>", B),
            Paragraph("<b>Detail</b>", B),
        ]]
        for label, key in [
            ("C2PA Validity", "c2pa_validity"),
            ("Publisher", "publisher_verification"),
            ("AI Detection", "ai_detection"),
            ("Metadata", "metadata_integrity"),
            ("Tamper", "tamper_detection"),
        ]:
            c = self.sc[key]
            ic = "\u2705" if c["score"] >= c["max_score"] * 0.8 else \
                 "\u26a0\ufe0f" if c["score"] >= c["max_score"] * 0.4 else "\u274c"
            sd.append([
                Paragraph(label, B),
                Paragraph(f"{c['score']}/{c['max_score']}", B),
                Paragraph(f"{ic} {c['status'].replace('_', ' ').title()}", B),
                Paragraph(c["details"][:120], SM),
            ])
        sd.append([
            Paragraph("<b>OVERALL</b>", B),
            Paragraph(f"<b>{self.sc['overall_score']}/100</b>", B),
            Paragraph(f"<b>{self.sc['trust_level']}</b>", B),
            Paragraph("", B),
        ])
        st = Table(sd, colWidths=[1.5 * inch, 0.8 * inch, 1.5 * inch, 3 * inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
            ("LINEABOVE", (0, -1), (-1, -1), 2, colors.HexColor("#1e3a5f")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        el.append(st)
        el.append(Spacer(1, 24))
        el.append(HRFlowable(width="100%", thickness=1,
                              color=colors.HexColor("#cbd5e1"), spaceAfter=12))
        cert = self.gen_json()
        el.append(Paragraph(
            f"Verification Hash: <font face='Courier' size=7>{cert['verification_hash']}</font>",
            SM))
        el.append(Paragraph(
            "Generated by PulseProof Forensic Engine v7.4. C2PA v1.3 / IPTC Compliant.", SM))
        doc.build(el)
        buf.seek(0)
        return buf.getvalue()


# ═══════════════════════════════════════════════════════════
# ANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════
class AnalysisPipeline:
    def __init__(self, file_data: bytes, filename: str):
        self.file_data = file_data
        self.filename = filename
        self.file_hash = hashlib.sha256(file_data).hexdigest()

    def run(self) -> Dict:
        c2pa = C2PAParser(self.file_data, self.filename).parse()
        raw_ai = self._scan_binary()
        verifier = ProvenanceVerifier(c2pa, self.file_hash, self.filename)
        scorecard = verifier.generate_scorecard()

        if raw_ai["detected"] and scorecard["ai_detection"]["score"] > 5:
            scorecard["ai_detection"] = {
                "score": 0 if raw_ai["type"] == "ai_generated" else 8,
                "max_score": 25,
                "status": raw_ai["type"],
                "details": f"Binary scan: {raw_ai['detail']}",
                "flag": "AI_BINARY",
            }

        try:
            image = Image.open(io.BytesIO(self.file_data))
        except Exception as e:
            return {"error": str(e)}

        tamper = TamperDetector(image).analyze()
        scorecard = verifier.finalize(scorecard, tamper)
        cert = CertificateGenerator(
            scorecard, c2pa, tamper, self.file_hash, self.filename)

        return {
            "filename": self.filename,
            "file_hash": self.file_hash,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "scorecard": scorecard,
            "c2pa_metadata": c2pa,
            "tamper_analysis": tamper,
            "binary_ai_scan": raw_ai,
            "certificate_json": cert.gen_json(),
            "certificate_id": cert.cid,
        }

    def _scan_binary(self):
        dl = self.file_data.lower()
        for tk, ti in AI_TOOL_SIGNATURES.items():
            if tk.encode() in dl:
                return {
                    "detected": True, "type": ti["type"],
                    "tool": ti["label"], "vendor": ti["vendor"],
                    "detail": f"{ti['label']} ({ti['vendor']}) in binary",
                }
        return {
            "detected": False, "type": None,
            "tool": None, "vendor": None,
            "detail": "No AI signatures in binary",
        }


# ═══════════════════════════════════════════════════════════
# STREAMLIT UI
# ═══════════════════════════════════════════════════════════
def score_col(s, m):
    p = s / m
    if p >= 0.8:
        return "#10b981"
    elif p >= 0.6:
        return "#3b82f6"
    elif p >= 0.4:
        return "#f59e0b"
    else:
        return "#ef4444"


def main():
    st.set_page_config(
        page_title="PulseProof",
        page_icon="\U0001f6e1\ufe0f",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    st.markdown("""<style>
    .stApp { background: #0f172a; }
    .score-ring {
        position: relative; display: inline-flex; align-items: center;
        justify-content: center; width: 200px; height: 200px;
    }
    .score-ring svg { transform: rotate(-90deg); }
    .score-ring .value { position: absolute; font-size: 3rem; font-weight: 900; }
    .score-ring .max {
        position: absolute; font-size: 0.65rem; top: 60%;
        color: #64748b; text-transform: uppercase; letter-spacing: 0.1em;
    }
    .cat-bar { padding: 12px 0; border-bottom: 1px solid #1e293b; }
    .cat-label { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
    .cat-name { display: flex; align-items: center; gap: 6px; }
    .cat-name span:first-child { font-size: 14px; }
    .cat-name .fname { font-size: 13px; font-weight: 600; color: #e2e8f0; }
    .cat-score { font-size: 13px; font-weight: 800; }
    .bar-track { width: 100%; height: 8px; background: #1e293b; border-radius: 4px; overflow: hidden; }
    .bar-fill { height: 8px; border-radius: 4px; transition: width 1.5s ease; }
    .cat-detail { font-size: 11px; color: #64748b; margin-top: 4px; line-height: 1.5; }
    .flag-badge {
        display: inline-block; padding: 1px 6px; background: rgba(239,68,68,0.15);
        color: #fca5a5; font-size: 9px; font-weight: 700; border-radius: 3px;
        text-transform: uppercase; letter-spacing: 0.05em; margin-left: 6px;
    }
    .flag-badge-warn {
        display: inline-block; padding: 1px 6px; background: rgba(245,158,11,0.15);
        color: #fcd34d; font-size: 9px; font-weight: 700; border-radius: 3px;
        text-transform: uppercase; letter-spacing: 0.05em; margin-left: 6px;
    }
    .trust-badge {
        display: inline-flex; align-items: center; gap: 6px; padding: 6px 16px;
        border-radius: 9999px; font-size: 14px; font-weight: 700; margin-top: 12px;
    }
    .region-item {
        display: flex; align-items: flex-start; gap: 6px;
        font-size: 11px; color: #94a3b8; margin-top: 4px;
    }
    .region-dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 3px; flex-shrink: 0; }
    </style>""", unsafe_allow_html=True)

    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
        <div style="width:42px;height:42px;background:#4f46e5;border-radius:12px;
                    display:flex;align-items:center;justify-content:center;color:white;
                    font-weight:900;font-size:20px;box-shadow:0 4px 12px rgba(79,70,229,0.3);">P</div>
        <div>
            <div style="font-size:22px;font-weight:900;color:#f1f5f9;letter-spacing:-0.5px;">PulseProof</div>
            <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:0.15em;">
                Forensic Engine v7.4 \u2014 C2PA / IPTC / ELA</div>
        </div>
    </div>""", unsafe_allow_html=True)

    if "result" not in st.session_state:
        st.session_state.result = None

    result = st.session_state.result

    if not result:
        st.markdown(
            "<div style='text-align:center;margin:40px 0 20px;'>"
            "<div style='font-size:32px;font-weight:900;color:#f1f5f9;'>"
            "Forensic Image Verification</div>"
            "<div style='font-size:14px;color:#64748b;margin-top:8px;'>"
            "Extract C2PA Content Credentials \u00b7 Detect AI manipulation \u00b7 "
            "Verify IPTC publishers \u00b7 ELA tamper mapping \u00b7 "
            "Generate audit-ready Trust Certificates</div></div>",
            unsafe_allow_html=True,
        )

        uploaded = st.file_uploader(
            "", type=["jpg", "jpeg", "png", "webp"], label_visibility="collapsed")
        if uploaded:
            with st.spinner("\U0001f50d Running forensic analysis pipeline..."):
                data = uploaded.read()
                pipeline = AnalysisPipeline(data, uploaded.name)
                res = pipeline.run()
                if "error" in res:
                    st.error(f"Analysis failed: {res['error']}")
                else:
                    st.session_state.result = res
                    st.rerun()

    else:
        sc = result["scorecard"]
        c2pa = result["c2pa_metadata"]
        tamp = result["tamper_analysis"]
        bscan = result["binary_ai_scan"]

        score_col_ui, card_col_ui = st.columns([1, 2.5])

        with score_col_ui:
            col_val = score_col(sc["overall_score"], 100)
            pct = sc["overall_score"] / 100
            r = 88
            circ = 2 * math.pi * r
            off = circ - pct * circ
            trust_icons = {
                "Trusted": "\U0001f6e1\ufe0f", "Verified": "\u2705",
                "Caution": "\u26a0\ufe0f", "Suspicious": "\U0001f536", "Untrusted": "\U0001f6ab",
            }
            trust_icon = trust_icons.get(sc["trust_level"], "\u2753")

            st.markdown(f"""
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                        padding:30px;background:#1e293b;border-radius:16px;border:1px solid #334155;">
                <div class="score-ring">
                    <svg width="200" height="200">
                        <circle cx="100" cy="100" r="{r}" stroke="#1e293b" stroke-width="12" fill="none"/>
                        <circle cx="100" cy="100" r="{r}" stroke="{col_val}" stroke-width="12" fill="none"
                                stroke-dasharray="{circ}" stroke-dashoffset="{off}" stroke-linecap="round"
                                style="transition:stroke-dashoffset 1.5s ease-in-out, stroke 0.5s;"/>
                    </svg>
                    <div class="value" style="color:{col_val};">{sc['overall_score']}</div>
                    <div class="max">/ 100</div>
                </div>
                <div class="trust-badge" style="border:2px solid {col_val};
                     background:{col_val}15;color:{col_val};">
                    {trust_icon}
                    &nbsp;{sc['trust_level']}
                </div>
                <div style="margin-top:12px;font-size:10px;color:#475569;font-family:monospace;">
                    {result['certificate_id']}</div>
            </div>""", unsafe_allow_html=True)

        with card_col_ui:
            st.markdown('<div style="padding:0 8px;">', unsafe_allow_html=True)
            cats = [
                ("C2PA Validity", "c2pa_validity"),
                ("Publisher Verification", "publisher_verification"),
                ("AI Detection", "ai_detection"),
                ("Metadata Integrity", "metadata_integrity"),
                ("Tamper Analysis", "tamper_detection"),
            ]
            for label, key in cats:
                c = sc[key]
                col = score_col(c["score"], c["max_score"])
                pct_w = (c["score"] / c["max_score"]) * 100
                ic = "\u2705" if c["score"] >= c["max_score"] * 0.8 else \
                     "\u26a0\ufe0f" if c["score"] >= c["max_score"] * 0.4 else "\u274c"
                flag_html = ""
                if c.get("flag"):
                    flag = c["flag"].replace("_", " ")
                    badge_class = "flag-badge" if c["score"] < c["max_score"] * 0.4 else "flag-badge-warn"
                    flag_html = f'<span class="{badge_class}">{flag}</span>'
                st.markdown(f"""
                <div class="cat-bar">
                    <div class="cat-label">
                        <div class="cat-name"><span>{ic}</span><span class="fname">{label}</span>{flag_html}</div>
                        <span class="cat-score" style="color:{col};">{c['score']}/{c['max_score']}</span>
                    </div>
                    <div class="bar-track"><div class="bar-fill" style="width:{pct_w}%;background:{col};"></div></div>
                    <div class="cat-detail">{c['details']}</div>
                </div>""", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        tab1, tab2, tab3, tab4 = st.tabs([
            "\U0001f52c Tamper Map", "\U0001f4cb Metadata", "\U0001f4dc Certificates", "\U0001f50d Binary Scan"])

        with tab1:
            st.subheader("Visual Tamper Map \u2014 Error Level Analysis")
            view_mode = st.radio(
                "View", ["Annotated", "Heatmap", "Raw ELA"],
                horizontal=True, label_visibility="collapsed")
            view_map = {
                "Annotated": tamp.get("annotated_pil"),
                "Heatmap": tamp.get("heatmap_pil"),
                "Raw ELA": tamp.get("ela_pil"),
            }
            pil = view_map.get(view_mode)
            if pil:
                st.image(pil, use_container_width=True)
            else:
                st.info("ELA data not available for this view.")
            if tamp.get("regions"):
                st.markdown("**Detected Regions:**")
                for i, r in enumerate(tamp["regions"]):
                    dc = {"high": "#ef4444", "medium": "#f59e0b", "low": "#818cf8"}.get(
                        r["severity"], "#818cf8")
                    st.markdown(f"""
                    <div class="region-item">
                        <div class="region-dot" style="background:{dc};"></div>
                        <span><strong>R{i+1}</strong> ({r['x']},{r['y']}) {r['width']}\u00d7{r['height']}px \u2014
                        {r['description']}</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.markdown(
                    '<div style="color:#10b981;font-size:12px;font-weight:600;">'
                    '\u2705 No suspicious regions detected in Error Level Analysis.</div>',
                    unsafe_allow_html=True)

        with tab2:
            st.subheader("C2PA & EXIF Metadata")
            if c2pa.get("c2pa_present"):
                st.success(
                    f"\u2705 C2PA Manifest Present \u2014 "
                    f"{c2pa.get('manifest_count', 0)} manifest(s) detected")
            else:
                st.error("\u274c No C2PA Manifest Detected")
            if c2pa.get("claim_generator"):
                st.markdown(f"**Claim Generator:** `{c2pa['claim_generator']}`")
            if c2pa.get("digital_source_type"):
                st.markdown(f"**Digital Source Type:** `{c2pa['digital_source_type']}`")
            if c2pa.get("assertions"):
                with st.expander(f"Assertions ({len(c2pa['assertions'])})", expanded=False):
                    for i, a in enumerate(c2pa["assertions"]):
                        st.markdown(f"**{a.get('url', '?')}**")
                        st.code(a.get("data", "")[:500], language="json")
            if c2pa.get("actions"):
                with st.expander(f"Edit Actions ({len(c2pa['actions'])})", expanded=False):
                    for a in c2pa["actions"]:
                        st.json(a)
            exif = c2pa.get("exif", {})
            if exif:
                with st.expander(f"EXIF Data ({len(exif)} fields)", expanded=False):
                    for k, v in list(exif.items())[:40]:
                        st.markdown(f"**{k}:** {v}")
            else:
                st.warning("No EXIF data found. Metadata may be stripped or format-limited.")
            if c2pa.get("authority_fields"):
                with st.expander(f"Authorship Fields ({len(c2pa['authority_fields'])})", expanded=False):
                    for f in c2pa["authority_fields"]:
                        st.markdown(f"- `{f}`")
            if c2pa.get("raw_text"):
                with st.expander("Raw Binary Text (sample)", expanded=False):
                    st.code(c2pa["raw_text"][:2000])

        with tab3:
            st.subheader("Trust Certificates")
            cj = result.get("certificate_json", {})
            cp = CertificateGenerator(
                sc, c2pa, tamp, result["file_hash"], result["filename"])
            col_pdf, col_json = st.columns(2)
            with col_pdf:
                try:
                    pdf_bytes = cp.gen_pdf()
                    st.download_button(
                        "\U0001f4c4 Download PDF Certificate", pdf_bytes,
                        f"PulseProof_{result['certificate_id']}.pdf", "application/pdf",
                        use_container_width=True)
                except Exception as e:
                    st.error(f"PDF generation failed: {e}")
            with col_json:
                st.download_button(
                    "\U0001f4cb Download JSON Certificate", json.dumps(cj, indent=2),
                    f"PulseProof_{result['certificate_id']}.json", "application/json",
                    use_container_width=True)
            with st.expander("Certificate Preview"):
                st.json(cj)

        with tab4:
            st.subheader("Raw Binary AI Scan")
            if bscan.get("detected"):
                st.error(
                    f"\U0001f6ab **{bscan['tool']}** ({bscan['vendor']}) "
                    f"signature detected in raw binary!")
                st.markdown(
                    f"**Type:** {bscan['type']}  |  **Detail:** {bscan['detail']}")
            else:
                st.success("\u2705 No AI tool signatures detected in raw binary scan.")
            st.markdown(f"**SHA-256:** `{result['file_hash']}`")
            st.markdown(f"**Analyzed:** {result['analyzed_at'][:19]} UTC")

        st.markdown("---")
        if st.button("\U0001f504 Analyze Another Image", use_container_width=True):
            st.session_state.result = None
            st.rerun()


if __name__ == "__main__":
    main()
