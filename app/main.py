import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    title="steg.api.mss.io"
)

REQUIRED_API_TOKEN = os.environ.get("API_TOKEN")
if not REQUIRED_API_TOKEN:
    raise RuntimeError("API_TOKEN environment variable must be set")


def require_api_token(x_api_token: str | None = Header(None, alias="x-api-token")):
    if not x_api_token or x_api_token != REQUIRED_API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-token")
    return x_api_token

ImageType = Literal["jpeg", "png"]

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
TEXT_IMAGE_SCRIPT = SCRIPT_DIR / "text-image-advance.py"


class HideRequest(BaseModel):
    image_type: ImageType
    image_base64: str
    secret_message: str
    password: str


class ShowRequest(BaseModel):
    image_type: ImageType
    image_base64: str
    password: str


@app.get("/")
def read_root(_: str = Depends(require_api_token)):
    return {"system": "steg.api.mss.io"}


@app.post("/hide")
def hide(body: HideRequest, _: str = Depends(require_api_token)):
    ext = "png" if body.image_type == "png" else "jpg"
    try:
        image_bytes = base64.b64decode(body.image_base64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image_base64: {e}")

    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as f_in:
        f_in.write(image_bytes)
        input_path = f_in.name

    output_path = input_path.replace(f".{ext}", f"_out.{ext}", 1)

    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(TEXT_IMAGE_SCRIPT),
                "hide",
                body.secret_message,
                body.password,
                input_path,
                output_path,
                "robust",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise HTTPException(
                status_code=422,
                detail=proc.stderr or proc.stdout or "Steganography script failed",
            )

        with open(output_path, "rb") as f_out:
            output_bytes = f_out.read()

        image_base64_out = base64.b64encode(output_bytes).decode("ascii")
        return {"image_type": body.image_type, "image_base64": image_base64_out}
    finally:
        Path(input_path).unlink(missing_ok=True)
        Path(output_path).unlink(missing_ok=True)

@app.post("/show")
def show(body: ShowRequest, _: str = Depends(require_api_token)):
    ext = "png" if body.image_type == "png" else "jpg"
    try:
        image_bytes = base64.b64decode(body.image_base64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image_base64: {e}")

    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as f_in:
        f_in.write(image_bytes)
        input_path = f_in.name

    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(TEXT_IMAGE_SCRIPT),
                "show",
                body.password,
                input_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise HTTPException(
                status_code=422,
                detail=proc.stderr or proc.stdout or "No hidden message found or wrong password",
            )

        # Script prints "Message: <secret>" on success
        secret_message = ""
        for line in (proc.stdout or "").strip().splitlines():
            if line.startswith("Message: "):
                secret_message = line[9:].strip()
                break

        return {"secret_message": secret_message}
    finally:
        Path(input_path).unlink(missing_ok=True)
