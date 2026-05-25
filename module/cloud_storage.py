from minio import Minio
from minio.error import S3Error
from logging_module import (
    log_info,
    log_error
)
import os
import json
from pathlib import Path

# ==============================
# ROOT DIRECTORY
# ==============================

ROOT_DIR = Path(__file__).resolve().parents[1]

CLOUD_STORAGE_DIR = (
    ROOT_DIR / "cloud_storage"
)

METADATA_DIR = (
    CLOUD_STORAGE_DIR / "metadata"
)

DOWNLOADS_DIR = (
    CLOUD_STORAGE_DIR / "downloads"
)

# create folders
METADATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)

DOWNLOADS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

# ==============================
# MINIO CONFIGURATION
# ==============================

MINIO_ENDPOINT = "localhost:9000"
MINIO_ACCESS_KEY = "admin"
MINIO_SECRET_KEY = "password123"

BUCKET_NAME = "secure-healthcare-storage"

# ==============================
# CONNECT TO MINIO
# ==============================

client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False
)

# ==============================
# CREATE BUCKET
# ==============================

def create_bucket():

    found = client.bucket_exists(BUCKET_NAME)

    if not found:
        client.make_bucket(BUCKET_NAME)
        print(f"[SUCCESS] Bucket created: {BUCKET_NAME}")

    else:
        print(f"[INFO] Bucket already exists")


# ==============================
# UPLOAD ENCRYPTED FILE
# ==============================

def upload_encrypted_file(local_path, filename):

    object_name = f"encrypted/{filename}"

    try:

        client.fput_object(
            BUCKET_NAME,
            object_name,
            local_path
        )

        print(f"[SUCCESS] Uploaded encrypted file: {filename}")

    except S3Error as e:
        log_error(f"Error uploading encrypted file {filename}: {e}")


# ==============================
# UPLOAD ENCRYPTED AES KEY
# ==============================

def upload_encrypted_key(local_path, filename):

    object_name = f"encrypted_keys/{filename}"

    try:

        client.fput_object(
            BUCKET_NAME,
            object_name,
            local_path
        )

        print(f"[SUCCESS] Uploaded encrypted AES key: {filename}")

    except S3Error as e:
        log_error(f"Error uploading encrypted AES key {filename}: {e}")


# ==============================
# UPLOAD METADATA
# ==============================

def upload_metadata(metadata_dict, filename):

    metadata_path = (
    METADATA_DIR / filename
    )

    # save metadata locally
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=4)

    object_name = f"metadata/{filename}"

    try:

        client.fput_object(
            BUCKET_NAME,
            object_name,
            metadata_path
        )

        print(f"[SUCCESS] Uploaded metadata: {filename}")

    except S3Error as e:
        log_error(f"Error uploading metadata {filename}: {e}")


# ==============================
# DOWNLOAD ENCRYPTED FILE
# ==============================

def download_encrypted_file(filename):

    object_name = f"encrypted/{filename}"

    download_path = (
    DOWNLOADS_DIR / filename
    )

    try:

        client.fget_object(
            BUCKET_NAME,
            object_name,
            download_path
        )

        print(f"[SUCCESS] Downloaded encrypted file: {filename}")

        return download_path

    except S3Error as e:
        log_error(f"Error downloading encrypted file {filename}: {e}"   )


# ==============================
# DOWNLOAD ENCRYPTED KEY
# ==============================

def download_encrypted_key(filename):

    object_name = f"encrypted_keys/{filename}"

    download_path = f"cloud_storage/downloads/{filename}"

    try:

        client.fget_object(
            BUCKET_NAME,
            object_name,
            download_path
        )

        print(f"[SUCCESS] Downloaded encrypted key: {filename}")

        return download_path

    except S3Error as e:
        print("[ERROR]", e)


# ==============================
# GET METADATA
# ==============================

def get_metadata(filename):

    object_name = f"metadata/{filename}"

    download_path = f"cloud_storage/downloads/{filename}"

    try:

        client.fget_object(
            BUCKET_NAME,
            object_name,
            download_path
        )

        with open(download_path, "r") as f:
            metadata = json.load(f)

        print(f"[SUCCESS] Metadata loaded")

        return metadata

    except S3Error as e:
        print("[ERROR]", e)