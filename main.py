import os
import pickle
import base64
import email
import time
import uuid
import random
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Define OAuth 2.0 scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.readonly"]

def authenticate_gmail():
    """Authenticate Gmail API using OAuth 2.0"""
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    return creds

def fetch_unread_emails(service):
    """Fetch unread emails from Gmail, excluding spam/promotions"""
    try:
        print("Checking for new emails...")
        results = service.users().messages().list(
            userId="me", labelIds=["INBOX"], q="is:unread", maxResults=10
        ).execute()
        messages = results.get("messages", [])
        return messages
    except HttpError as error:
        print(f"An error occurred: {error}")
        return []

def generate_custom_message_id(thread_id):
    """Generate a custom Message-ID similar to Thread-ID"""
    unique_part = uuid.uuid4().hex
    return f"<{unique_part}@mail.gmail.com>"

def avoid_spam_emails(service, msg_id):
    """Check if the email is in spam/promotions and avoid replying"""
    try:
        msg_data = service.users().messages().get(userId="me", id=msg_id, format="metadata").execute()
        labels = msg_data.get("labelIds", [])

        # If the email is in SPAM or PROMOTIONS, do not reply
        if "SPAM" in labels or "CATEGORY_PROMOTIONS" in labels:
            print(f"Skipping spam/promotions email {msg_id}")
            return False
        return True
    except HttpError as error:
        print(f"Error checking labels: {error}")
        return False

def generate_reply_content(subject):
    """Generate a dynamic reply to prevent detection as automated messages"""
    responses = [
        "Thank you for reaching out. I will review your message and get back to you.",
        "I appreciate your email. I will respond as soon as possible.",
        "Hello, your email has been received. I will get back to you soon.",
        "I’m currently unavailable but will reply to your email as soon as I can."
    ]
    return random.choice(responses)  # Randomize responses to avoid spam filters

def send_reply_email(service, to_email, subject, body, thread_id, message_id):
    """Send a reply email using Gmail API within the same thread"""
    try:
        custom_message_id = generate_custom_message_id(thread_id)

        message = email.message.EmailMessage()
        message["To"] = to_email
        message["Subject"] = subject
        message["In-Reply-To"] = message_id
        message["References"] = message_id
        message["Message-ID"] = custom_message_id
        message.set_content(body)

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        send_message = service.users().messages().send(
            userId="me", body={"raw": encoded_message, "threadId": thread_id}
        ).execute()

        print(f"Auto-reply sent to {to_email}, Message ID: {custom_message_id}")

    except HttpError as error:
        print(f"An error occurred: {error}")
def send_email(to_email, subject, body):
    """Send an email using Gmail API"""
    try:
        creds = authenticate_gmail()
        service = build("gmail", "v1", credentials=creds)

        message = email.message.EmailMessage()
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        send_message = service.users().messages().send(
            userId="me", body={"raw": encoded_message}
        ).execute()

        print(f"Auto-reply sent to {to_email}, Message ID: {send_message['id']}")

    except HttpError as error:
        print(f"An error occurred: {error}")

def exponential_backoff(attempt):
    """Implement exponential backoff to handle rate limits"""
    wait_time = min(60, (2 ** attempt) + random.uniform(0, 1))
    print(f"Rate limit reached. Retrying in {wait_time:.2f} seconds...")
    time.sleep(wait_time)

def auto_reply():
    """Automatically replies to unread emails within the same thread"""
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    messages = fetch_unread_emails(service)

    if not messages:
        print("No unread emails found.")
        return

    attempt = 0
    for msg in messages:
        msg_id = msg["id"]

        # Check if the email is spam or promotions
        if not avoid_spam_emails(service, msg_id):
            continue  # Skip this email

        try:
            msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

            headers = msg_data["payload"]["headers"]
            sender = next((header["value"] for header in headers if header["name"] == "From"), "Unknown Sender")
            subject = next((header["value"] for header in headers if header["name"] == "Subject"), "No Subject")
            message_id = next((header["value"] for header in headers if header["name"] == "Message-ID"), None)
            thread_id = msg_data.get("threadId", None)

            if not message_id or not thread_id:
                print("Skipping email due to missing Message-ID or Thread-ID.")
                continue

            print(f"Replying to: {sender}, Subject: {subject}")
            reply_body = generate_reply_content(subject)
            send_reply_email(service, sender, "Re: " + subject, reply_body, thread_id, message_id)

            # Implement random delays (2-10 sec) to avoid being flagged as a bot
            time.sleep(random.uniform(2, 10))

        except HttpError as error:
            if error.resp.status in [403, 429]:  # Handle rate limit errors
                exponential_backoff(attempt)
                attempt += 1
                continue
            else:
                print(f"An error occurred: {error}")

# Run the auto-reply function
send_email("recipient@example.com","Test Subject","Test Body")
auto_reply()