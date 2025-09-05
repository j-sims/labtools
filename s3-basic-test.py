#!/usr/bin/env python3
"""
Enhanced S3 basic test harness.

Reads hosts.json and for each host:
"""
import json
import os
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, EndpointConnectionError
except Exception as e:
    # Provide a friendly message if boto3 is not installed
    print("Error: boto3 is required for s3-basic-test.py. Install with: pip install boto3")
    raise


def load_hosts(path: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Hosts file not found: {path}")
    with open(path, "r") as f:
        data = json.load(f)
    return data


def derive_endpoint(host: Dict[str, Any]) -> str:
    """
    Build the endpoint URL for a host.
    - If host.s3_endpoint is provided and non-empty, return it as-is.
    - Otherwise, derive from hostname, s3_port (default 9000), and SSL setting.
    """
    if "s3_endpoint" in host and host["s3_endpoint"]:
        return host["s3_endpoint"]
    hostname = host.get("hostname")
    # Determine scheme with backward-compatible alias: s3_use_ssl takes precedence,
    # then s3_ssl, then default to True
    use_ssl = host.get("s3_use_ssl", host.get("s3_ssl", True))
    scheme = "https" if use_ssl else "http"
    # Determine port
    port = host.get("s3_port", 9000)
    port_str = str(port) if port is not None else "9000"
    return f"{scheme}://{hostname}:{port_str}"


def build_s3_client(host: Dict[str, Any], endpoint: str) -> Any:
    region = host.get("s3_region", "us-east-1")
    # Consistent SSL decision with the same precedence as derive_endpoint
    use_ssl = host.get("s3_use_ssl", host.get("s3_ssl", True))
    sig_ver = host.get("s3_signature_version", "s3v4")
    access_key = host.get("s3_acc_id")
    secret_key = host.get("s3_secret_key")

    # Optional: quiet signing config hints to boto3 / botocore
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        use_ssl=use_ssl,
        # signature_version can be 's3v4' or 's3', but many S3-compatible endpoints require v4
        config=Config(signature_version=sig_ver),
    )
    return client


def test_host(host: Dict[str, Any], timeout: float, verbose: bool, file_path: str, object_key: Optional[str]) -> Dict[str, Any]:
    hostname = host.get("hostname", "unknown")
    endpoint = derive_endpoint(host)
    bucket_name = "test"
    result: Dict[str, Any] = {"host": hostname, "endpoint": endpoint, "bucket": bucket_name}
    if verbose:
        print(f"[{hostname}] Starting S3 test against {endpoint} (bucket={bucket_name})")
    # Validate local file path early
    if not file_path or not os.path.isfile(file_path):
        result.update({"status": "failed", "error": "invalid_input", "message": "Local file does not exist: {}".format(file_path)})
        return result
    try:
        client = build_s3_client(host, endpoint)
        # Ensure bucket "test" exists / is accessible by performing a lightweight operation
        client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        # Pre-upload snapshot
        pre_resp = client.list_objects_v2(Bucket=bucket_name)
        pre_keys = [obj.get("Key") for obj in pre_resp.get("Contents", [])]
        # Determine final key
        final_key = object_key or os.path.basename(file_path)
        # Upload the file
        with open(file_path, "rb") as f:
            client.put_object(Bucket=bucket_name, Key=final_key, Body=f)
        # Post-upload snapshot
        post_resp = client.list_objects_v2(Bucket=bucket_name)
        post_keys = [obj.get("Key") for obj in post_resp.get("Contents", [])]
        status = "complete" if final_key in post_keys else "failed"
        result.update({
            "status": status,
            "pre_keys": pre_keys,
            "post_keys": post_keys,
            "uploaded_key": final_key
        })
        if verbose:
            print(f"[{hostname}] Pre-keys: {pre_keys}")
            print(f"[{hostname}] Post-keys: {post_keys}")
        return result if status == "complete" else {**result, "error": "upload_failed", "message": "Uploaded key not found after upload"}
    except EndpointConnectionError as e:
        result.update({"status": "failed", "error": "endpoint_connection_error", "message": str(e)})
        return result
    except ClientError as e:
        # boto3 wraps service errors; include error code for quick triage
        error_code = e.response.get("Error", {}).get("Code")
        result.update({"status": "failed", "error": "client_error", "code": error_code, "message": str(e)})
        return result
    except Exception as e:
        result.update({"status": "failed", "error": "unexpected_error", "message": str(e)})
        return result


def main():
    parser = argparse.ArgumentParser(description="s3-basic-test: verify S3-compatible endpoints per host.")
    parser.add_argument("--hosts-file", type=str, default="hosts.json", help="Path to hosts.json (default: hosts.json)")
    parser.add_argument("--timeout", type=float, default=20.0, help="Per-host operation timeout in seconds (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose per-host output")
    parser.add_argument("-f", "--file", type=str, required=True, help="Local file path to upload to bucket 'test'")
    parser.add_argument("-k", "--object-key", dest="object_key", type=str, default=None, help="Optional S3 object key. Defaults to basename of -f")
    args = parser.parse_args()

    # Validate file early
    if not args.file or not os.path.isfile(args.file):
        print(f"Error: Local file does not exist: {args.file}")
        raise SystemExit(2)
    hosts = load_hosts(args.hosts_file)

    results: List[Dict[str, Any]] = []
    futures = []
    with ThreadPoolExecutor(max_workers=min(32, len(hosts) or 1)) as executor:
        for host in hosts:
            futures.append(executor.submit(test_host, host, args.timeout, args.verbose, args.file, args.object_key))

        for fut in as_completed(futures, timeout=None):
            try:
                res = fut.result(timeout=None)
            except Exception as e:
                # Shouldn't generally happen since test_host handles its own errors
                res = {"host": "unknown", "status": "failed", "error": "unknown_error", "message": str(e)}
            results.append(res)

    # Sort results by host for deterministic output
    results.sort(key=lambda x: x.get("host", ""))

    # Print a concise summary
    print("\nS3 basic-test summary:")
    all_ok = True
    for r in results:
        host = r.get("host", "")
        endpoint = r.get("endpoint", "")
        status = r.get("status", "unknown")
        if status != "complete":
            all_ok = False
        if status == "complete":
            print(f" - Host: {host} | Endpoint: {endpoint} | Status: COMPLETE ✓")
        else:
            msg = r.get("message") or r.get("error") or "unknown_error"
            code = r.get("code")
            if code:
                summary = f"Status: {status} ({code}) - {msg}"
            else:
                summary = f"Status: {status} - {msg}"
            print(f" - Host: {host} | Endpoint: {endpoint} | {summary}")

    exit_code = 0 if all_ok else 2
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
