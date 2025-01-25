import os
import pickle
import base64
import email
import time
import uuid
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
    """Fetch unread emails from Gmail"""
    try:
        print("Checking for new emails...")
        results = service.users().messages().list(
            userId="me", labelIds=["INBOX"], q="is:unread", maxResults=5
        ).execute()
        messages = results.get("messages", [])
        return messages
    except HttpError as error:
        print(f"An error occurred: {error}")
        return []

def generate_custom_message_id(thread_id):
    """Generate a custom Message-ID similar to Thread-ID"""
    unique_part = uuid.uuid4().hex  # Generate a unique string using UUID
    custom_message_id = f"<{unique_part}@mail.gmail.com>"  # Append domain to make it look like a message ID
    return custom_message_id


def move_email_to_inbox(service, msg_id):
    """Move an email from Spam/Promotions to Inbox"""
    try:
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={
                "addLabelIds": ["INBOX"],
                "removeLabelIds": ["SPAM", "CATEGORY_PROMOTIONS"]
            }
        ).execute()
        print(f"Moved email {msg_id} to Inbox.")
    except HttpError as error:
        print(f"An error occurred while moving email: {error}")


def generate_reply_content(subject):
    """Generate different replies based on the subject"""
    if "Urgent" in subject:
        return "Hello, this is an automated response. Your urgent request is being processed."
    elif "Meeting" in subject:
        return "Hello, I received your email about the meeting. I will get back to you soon."
    else:
        return "Hello, thank you for reaching out. I will respond shortly."


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


def send_reply_email(service, to_email, subject, body, thread_id, message_id):
    """Send a reply email using Gmail API within the same thread with custom Message-ID"""
    try:
        # Generate custom Message-ID similar to Thread-ID
        custom_message_id = generate_custom_message_id(thread_id)

        message = email.message.EmailMessage()
        message["To"] = to_email
        message["Subject"] = subject
        message["In-Reply-To"] = message_id  # Referencing the original message
        message["References"] = message_id  # Important for threading
        message["Message-ID"] = custom_message_id  # Add custom Message-ID
        message.set_content(body)

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        send_message = service.users().messages().send(
            userId="me", body={"raw": encoded_message, "threadId": thread_id}  # Maintain thread
        ).execute()

        print(f"Auto-reply sent to {to_email}, Message ID: {custom_message_id}")

    except HttpError as error:
        print(f"An error occurred: {error}")


def auto_reply():
    """Automatically replies to unread emails within the same thread"""
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    messages = fetch_unread_emails(service)

    if not messages:
        print("No unread emails found.")
        return

    for msg in messages:
        msg_id = msg["id"]
        msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

        headers = msg_data["payload"]["headers"]
        sender = next((header["value"] for header in headers if header["name"] == "From"), "Unknown Sender")
        subject = next((header["value"] for header in headers if header["name"] == "Subject"), "No Subject")
        message_id = next((header["value"] for header in headers if header["name"] == "Message-ID"), None)
        thread_id = msg_data.get("threadId", None)

        # Debugging: Print message_id and thread_id for each email
        print(f"Fetched email. Message-ID: {message_id}, Thread-ID: {thread_id}")

        if not message_id or not thread_id:
            print("Skipping email due to missing Message-ID or Thread-ID.")
            continue

        print(f"Replying to: {sender}, Subject: {subject}")
        send_reply_email(service, sender, "Re: " + subject, "Hello, this is an automated reply.", thread_id, message_id)

# Run the auto-reply function
send_email("receiver_email@example.com","Test Subject","Test Body")
auto_reply()