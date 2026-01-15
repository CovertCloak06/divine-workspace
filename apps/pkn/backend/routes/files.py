"""
Files Routes Blueprint
Extracted from divinenode_server.py
"""

from flask import Blueprint, request, jsonify
import json
import uuid
from pathlib import Path
import os
import time
import contextlib


# Create blueprint
files_bp = Blueprint("files", __name__)

# File storage configuration
UPLOAD_DIR = Path(__file__).parent.parent.parent / "uploads"
META_FILE = UPLOAD_DIR / "files.json"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    # Documents
    "txt", "pdf", "doc", "docx", "odt", "rtf",
    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp",
    # Code
    "py", "js", "html", "css", "json", "xml", "yaml", "yml",
    "c", "cpp", "h", "hpp", "java", "rs", "go", "sh", "md",
    # Data
    "csv", "tsv", "xlsx", "xls",
    # Archives
    "zip", "tar", "gz", "bz2", "7z",
    # Other
    "log", "ini", "cfg", "conf",
}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _load_meta():
    """Load file metadata for uploads"""
    try:
        if META_FILE.exists():
            return json.loads(META_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_meta(meta):
    """Save file metadata for uploads"""
    with contextlib.suppress(Exception):
        META_FILE.write_text(json.dumps(meta, indent=2))


@files_bp.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "No selected file"}), 400

        # Validate file extension
        if not allowed_file(f.filename):
            return jsonify({"error": "File type not allowed"}), 400

        # Check file size (read content to validate)
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        f.seek(0)  # Reset to beginning

        if file_size > MAX_FILE_SIZE:
            return jsonify(
                {
                    "error": f"File too large. Max size: {MAX_FILE_SIZE // (1024 * 1024)}MB"
                }
            ), 400

        if file_size == 0:
            return jsonify({"error": "File is empty"}), 400

        # generate id and store
        fid = str(uuid.uuid4())
        safe_name = os.path.basename(f.filename)
        # Additional security: sanitize filename
        safe_name = safe_name.replace("..", "").replace("/", "").replace("\\", "")
        dest = UPLOAD_DIR / f"{fid}_{safe_name}"
        f.save(dest)

        # basic metadata
        meta = _load_meta()
        meta[fid] = {
            "id": fid,
            "filename": safe_name,
            "stored_name": dest.name,
            "size": dest.stat().st_size,
            "uploaded_at": int(time.time()),
        }
        _save_meta(meta)

        return jsonify(
            {"id": fid, "filename": safe_name, "size": meta[fid]["size"]}
        ), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/list", methods=["GET"])
def list_files():
    try:
        meta = _load_meta()
        files = list(meta.values())
        # sort by uploaded_at desc
        files.sort(key=lambda x: x.get("uploaded_at", 0), reverse=True)
        return jsonify({"files": files}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/<file_id>/summary", methods=["GET"])
def file_summary(file_id):
    try:
        meta = _load_meta()
        entry = meta.get(file_id)
        if not entry:
            return jsonify({"error": "File not found"}), 404

        path = UPLOAD_DIR / entry["stored_name"]
        if not path.exists():
            return jsonify({"error": "Stored file missing"}), 404

        # Only attempt to read text files (simple heuristic)
        try:
            text = path.read_text(errors="ignore")
        except Exception as e:
            return jsonify({"error": f"Could not read file: {str(e)}"}), 500

        snippet = text[:3000]
        # simple summary: first 500 chars + top words
        first = snippet[:500]
        words = [w.strip('.,:;"\'"()[]{}').lower() for w in snippet.split()]
        # Stopwords for summary (see app.js for similar logic in chat summarization)
        stop = {
            "the",
            "and",
            "for",
            "that",
            "with",
            "this",
            "from",
            "are",
            "was",
            "were",
            "have",
            "has",
            "will",
            "you",
            "your",
            "not",
            "but",
            "can",
            "our",
            "all",
            "any",
            "too",
            "its",
            "it's",
        }
        freq = {}
        for w in words:
            if len(w) < 3 or w in stop:
                continue
            freq[w] = freq.get(w, 0) + 1
        top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:8]
        keywords = [k for k, v in top]

        return jsonify(
            {
                "id": file_id,
                "filename": entry["filename"],
                "summary": first,
                "keywords": keywords,
            }
        ), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    try:
        meta = _load_meta()
        entry = meta.get(file_id)
        if not entry:
            return jsonify({"error": "File not found"}), 404

        file_path = UPLOAD_DIR / entry["stored_name"]
        if file_path.exists():
            os.remove(file_path)

        del meta[file_id]
        _save_meta(meta)

        return jsonify({"message": "File deleted successfully", "id": file_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===== FILE EXPLORER ENDPOINTS =====


@files_bp.route("/browse", methods=["POST"])
def browse_directory():
    """Browse files in a directory"""
    try:
        data = request.json
        path = data.get("path", "/")

        # Security: Prevent directory traversal
        if ".." in path or path.startswith("~"):
            return jsonify({"error": "Invalid path"}), 400

        # Convert to Path object
        from pathlib import Path
        import stat

        dir_path = Path(path)

        if not dir_path.exists():
            return jsonify({"error": "Path does not exist"}), 404

        if not dir_path.is_dir():
            return jsonify({"error": "Path is not a directory"}), 400

        files = []
        try:
            for item in dir_path.iterdir():
                try:
                    stats = item.stat()
                    files.append(
                        {
                            "name": item.name,
                            "type": "directory" if item.is_dir() else "file",
                            "size": stats.st_size if item.is_file() else 0,
                            "modified": stats.st_mtime,
                        }
                    )
                except (PermissionError, OSError):
                    # Skip files we can't access
                    continue
        except PermissionError:
            return jsonify({"error": "Permission denied"}), 403

        return jsonify({"path": str(dir_path), "files": files}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/download", methods=["POST"])
def download_file_from_path():
    """Download a file from filesystem"""
    try:
        data = request.json
        path = data.get("path", "")

        # Security: Prevent directory traversal
        if ".." in path or path.startswith("~"):
            return jsonify({"error": "Invalid path"}), 400

        from pathlib import Path

        file_path = Path(path)

        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404

        if not file_path.is_file():
            return jsonify({"error": "Path is not a file"}), 400

        from flask import send_file

        return send_file(
            str(file_path), as_attachment=True, download_name=file_path.name
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/view", methods=["POST"])
def view_file_content():
    """View text file content"""
    try:
        data = request.json
        path = data.get("path", "")
        max_lines = data.get("max_lines", 500)

        # Security: Prevent directory traversal
        if ".." in path or path.startswith("~"):
            return jsonify({"error": "Invalid path"}), 400

        from pathlib import Path

        file_path = Path(path)

        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404

        if not file_path.is_file():
            return jsonify({"error": "Path is not a file"}), 400

        # Check file size (limit to 10MB for text view)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return jsonify({"error": "File too large to view (max 10MB)"}), 400

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        return jsonify(
                            {
                                "content": "".join(lines),
                                "truncated": True,
                                "lines_read": i,
                            }
                        ), 200
                    lines.append(line)

                return jsonify(
                    {
                        "content": "".join(lines),
                        "truncated": False,
                        "lines_read": len(lines),
                    }
                ), 200
        except UnicodeDecodeError:
            return jsonify(
                {"error": "File is not a text file or has invalid encoding"}
            ), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/delete", methods=["POST"])
def delete_filesystem_item():
    """Delete a file or directory"""
    try:
        data = request.json
        path = data.get("path", "")
        recursive = data.get("recursive", False)

        # Security: Prevent directory traversal
        if ".." in path or path.startswith("~"):
            return jsonify({"error": "Invalid path"}), 400

        from pathlib import Path
        import shutil

        item_path = Path(path)

        if not item_path.exists():
            return jsonify({"error": "Path not found"}), 404

        # Additional safety: Don't allow deleting critical system directories
        critical_paths = ["/sdcard", "/data/data/com.termux/files/home", "/"]
        if str(item_path) in critical_paths:
            return jsonify({"error": "Cannot delete critical system directory"}), 403

        if item_path.is_dir():
            if not recursive:
                # Check if directory is empty
                if any(item_path.iterdir()):
                    return jsonify(
                        {"error": "Directory not empty. Use recursive delete."}
                    ), 400
                item_path.rmdir()
            else:
                shutil.rmtree(item_path)
        else:
            item_path.unlink()

        return jsonify({"message": "Deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@files_bp.route("/mkdir", methods=["POST"])
def create_directory():
    """Create a new directory"""
    try:
        data = request.json
        path = data.get("path", "")

        # Security: Prevent directory traversal
        if ".." in path or path.startswith("~"):
            return jsonify({"error": "Invalid path"}), 400

        from pathlib import Path

        dir_path = Path(path)

        if dir_path.exists():
            return jsonify({"error": "Path already exists"}), 400

        dir_path.mkdir(parents=False, exist_ok=False)

        return jsonify(
            {"message": "Directory created successfully", "path": str(dir_path)}
        ), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================
# CODE EDITOR API ENDPOINTS
# ============================================
