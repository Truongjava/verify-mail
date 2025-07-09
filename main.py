from flask import Flask, request, jsonify
import smtplib
import dns.resolver
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor
from dns.exception import DNSException
import logging
from functools import lru_cache

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Constants
SMTP_TIMEOUT = 40
SCRIPT_TIMEOUT = 20000
WORKER_THREADS = 50

executor = ThreadPoolExecutor(max_workers=WORKER_THREADS)

@lru_cache(maxsize=1024)
def get_mx_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = SMTP_TIMEOUT
    try:
        mx_records = resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange)
    except dns.resolver.NoAnswer:
        app.logger.error(f"No MX records found for {domain}")
    except dns.resolver.NXDOMAIN:
        app.logger.error(f"Domain does not exist: {domain}")
    except DNSException as e:
        app.logger.error(f"DNS query failed for {domain}: {e}")
    return None

def is_catch_all(mx_record, domain):
    try:
        with smtplib.SMTP(mx_record, 25, timeout=SMTP_TIMEOUT) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('radam@paidclient.com')
            random_email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@' + domain
            code, _ = server.rcpt(random_email)
            return code == 250
    except Exception as e:
        app.logger.warning(f"Catch-all check failed for {domain}: {e}")
        return False

def smtp_handshake(mx_record, email):
    try:
        with smtplib.SMTP(mx_record, 25, timeout=SMTP_TIMEOUT) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('radam@paidclient.com')
            code, message = server.rcpt(email)
            print(f"[SMTP DEBUG] RCPT to {email}: {code} - {message}")
            if code == 250:
                return True, None
            else:
                error_message = message.decode('utf-8') if message else 'Unknown error'
                return False, error_message
    except smtplib.SMTPServerDisconnected:
        return False, "SMTP server disconnected unexpectedly"
    except smtplib.SMTPResponseException as e:
        error_message = f"{e.smtp_code}, {e.smtp_error.decode('utf-8')}"
        return False, error_message
    except Exception as e:
        return False, f"SMTP handshake failed: {str(e)}"

def categorize_email(is_valid, is_catch_all, error=None):
    if is_valid and not is_catch_all:
        return 'Good'
    elif is_valid and is_catch_all:
        return 'Accept-All'
    elif not is_valid and is_catch_all:
        return 'Accept-All'
    elif error:
        return 'Risky'
    return 'Invalid'

def process_single_email(email):
    result = {
        "email": email,
        "category": "Invalid",
        "valid": "Invalid",
        "catch_all": "Unknown",
        "error": None
    }

    try:
        domain = email.split('@')[-1]
        mx_record = get_mx_record(domain)
        if not mx_record:
            result["error"] = f"No MX record for domain {domain}"
            return result

        is_valid, error_message = smtp_handshake(mx_record, email)
        is_catch_all_result = is_catch_all(mx_record, domain) if is_valid else False

        result.update({
            "category": categorize_email(is_valid, is_catch_all_result, error=error_message),
            "valid": "Valid" if is_valid else "Invalid",
            "catch_all": "Yes" if is_catch_all_result else "No",
            "error": error_message
        })

        print(f"[RESULT] {email} | Valid: {is_valid} | Catch-All: {is_catch_all_result} | Error: {error_message}")

        return result
    except Exception as e:
        result["error"] = f"Exception occurred: {str(e)}"
        return result

@app.route('/')
def home():
    return 'Email verification API is running'

@app.route('/email_verification', methods=['POST'])
def email_verification():
    try:
        start_time = time.time()
        app.logger.info("Email verification started")

        request_json = request.get_json()
        if not request_json or 'emails' not in request_json:
            return jsonify({"error": "No email addresses provided"}), 400

        emails = request_json['emails']
        future_results = [executor.submit(process_single_email, email) for email in emails]
        results = []
        for future in future_results:
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                app.logger.error(f"Thread error: {e}")
                results.append({
                    "email": "unknown",
                    "category": "Risky",
                    "valid": "Unknown",
                    "catch_all": "Unknown",
                    "error": "Thread execution failed"
                })

        total_time = time.time() - start_time
        app.logger.info(f"Email verification completed in {total_time:.2f} seconds")

        return jsonify({
            "results": results,
            "execution_time": f"{total_time:.2f} seconds"
        })

    except Exception as e:
        app.logger.error(f"Unhandled exception during verification: {e}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.errorhandler(Exception)
def handle_general_exception(error):
    app.logger.error(f"Unhandled error: {error}")
    return jsonify({"error": "Unhandled server error", "details": str(error)}), 500

if __name__ == "__main__":
    app.run(debug=True)
