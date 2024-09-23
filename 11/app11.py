from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
import time
import requests
import csv
import os
import urllib3
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError
from msal import ConfidentialClientApplication
import hashlib
import base64
import logging
logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(filename='app.log', level=logging.DEBUG)
logging.getLogger('apscheduler').setLevel(logging.DEBUG) # Configure APScheduler logging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable SSL warnings (optional for dev environments)
logging.basicConfig(filename='email_monitor.log', level=logging.INFO) # Configure logging to a file

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Global variables to store MISP credentials and Microsoft Graph credentials
misp_url = None
misp_key = None
shuffle_url = None
shuffle_api_key = None
csv_file_path = "fetched_iocs.csv"
microsoft_graph_token = None
token_expiration_time = 0
microsoft_graph_headers = None
stored_access_token = None
CLIENT_ID = '<your-client-id>'
CLIENT_SECRET = '<your-client-secret>'
client_id = '<your-client-id>'
client_secret = '<your-client-secret>'
tenant_id = '<your-tenant-id>'
graph_client_id = None
graph_client_secret = None
graph_tenant_id = None
TENANT_ID = 'common'  # Use 'common' to support personal Microsoft accounts
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = "https://localhost:9000/callback"  # Must match your registered redirect URI
SCOPE = ['User.Read', 'Mail.ReadWrite', 'Mail.send']  # Delegated permissions
token_expiration_time = 0

# Temporary folder for downloaded attachments
TEMP_ATTACHMENT_DIR = 'attachments'
if not os.path.exists(TEMP_ATTACHMENT_DIR):
    os.makedirs(TEMP_ATTACHMENT_DIR)

# Setup Background Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Microsoft Graph API Credentials
graph_scope = ['https://graph.microsoft.com/.default']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_misp_credentials', methods=['GET', 'POST'])
def add_misp_credentials():
    global misp_url, misp_key
    if request.method == 'POST':
        misp_url = request.form['misp_url']
        misp_key = request.form['misp_key']
        if misp_url and misp_key:
            logging.info("MISP credentials added successfully.", "success")
            return redirect(url_for('fetch_both'))
        else:
            logging.error("MISP credentials are missing. Please provide them.", "danger")
            return redirect(url_for('add_misp_credentials'))
    return render_template('add_misp_credentials.html')


# Route to fetch phishing, ransomware, and both events
@app.route('/fetch_both', methods=['GET', 'POST'])
def fetch_both():
    global phishing_events, ransomware_events, both_events
    if not misp_url or not misp_key:
        logging.error("MISP credentials are missing. Please provide them.", "danger")
        return redirect(url_for('add_misp_credentials'))
    
    # Log MISP URL and key for debugging
    print(f"Using MISP URL: {misp_url}")
    print(f"Using MISP API Key: {misp_key}")

    phishing_events = fetch_misp_events_by_keyword("phishing")
    ransomware_events = fetch_misp_events_by_keyword("ransomware")

    phishing_ids = set(event['id'] for event in phishing_events)
    ransomware_ids = set(event['id'] for event in ransomware_events)
    both_ids = phishing_ids.intersection(ransomware_ids)

    both_events = [event for event in phishing_events if event['id'] in both_ids]
    phishing_events = [event for event in phishing_events if event['id'] not in both_ids]
    ransomware_events = [event for event in ransomware_events if event['id'] not in both_ids]

    return render_template('select_events.html', phishing_events=phishing_events, ransomware_events=ransomware_events, both_events=both_events)


# Function to fetch events by keyword
def fetch_misp_events_by_keyword(keyword):
    headers = {
        'Authorization': misp_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    url = f'{misp_url}/events/index'
    events = []
    page = 1

    while True:
        data = {
            'searchall': keyword,
            'limit': 100,
            'page': page
        }
        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            if response.status_code == 200:
                event_page = response.json()
                if isinstance(event_page, list):
                    for event in event_page:
                        event_id = event.get('id')
                        event_info = event.get('info')
                        events.append({'id': event_id, 'info': event_info})
                    if len(event_page) < 100:
                        break
                    page += 1
                else:
                    break
            else:
                logging.error(f"Failed to fetch events: {response.text}", "danger")
                break
        except Exception as e:
            logging.error(f"Error fetching events: {e}", "danger")
            break

    return events


# Helper function for tagging an event
def tag_event(event_id, tag_name, headers):
    data = {'tag': tag_name}
    tag_url = f"{misp_url}/events/addTag/{event_id}"
    
    try:
        response = requests.post(tag_url, headers=headers, json=data, verify=False)
        if response.status_code == 200:
            logging.info(f"Successfully tagged event {event_id} with tag '{tag_name}'", "success")
            return True
        else:
            logging.error(f"Failed to tag event {event_id} with tag '{tag_name}': {response.text}", "danger")
            return False
    except Exception as e:
        logging.error(f"Exception occurred while tagging event {event_id} with {tag_name}: {e}")
        return False


@app.route('/fetch_iocs', methods=['POST'])
def fetch_iocs():
    global iocs_csv_file_path, tagged_csv_file_path
    selected_event_ids = request.form.getlist('selected_events')
    logging.info("Fetching IOCs and tagging events started.")
    logging.info(f"Selected event IDs: {selected_event_ids}")

    if not selected_event_ids:
        logging.warning("No events selected.")
        flash("No events selected.", "danger")
        return redirect(url_for('fetch_both'))

    tagged_event_count = {'phishing': 0, 'ransomware': 0, 'total': 0}
    PHISHING_TAGS = ['phishing']
    RANSOMWARE_TAGS = ['ransomware']

    try:
        # Ensure the CSV directory exists
        csv_dir = os.path.join(os.getcwd(), 'csv')
        if not os.path.exists(csv_dir):
            os.makedirs(csv_dir)

        # Path to save the CSV file for IOCs and tagged events
        iocs_csv_file_path = os.path.join(csv_dir, 'fetched_iocs.csv')
        tagged_csv_file_path = os.path.join(csv_dir, 'tagged_events.csv')

        # Open CSV for writing tagged events
        with open(tagged_csv_file_path, mode='w', newline='', encoding='utf-8') as tagged_file:
            tagged_writer = csv.writer(tagged_file)
            tagged_writer.writerow(["Sr. No.", "Event ID", "Tags"])

            headers = {
                'Authorization': misp_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            for idx, event_id in enumerate(selected_event_ids, 1):
                event_tags = []

                # Tagging logic based on event category
                if event_id in [event['id'] for event in phishing_events]:
                    tag_event(event_id, PHISHING_TAGS[0], headers)
                    event_tags.append(PHISHING_TAGS[0])
                    tagged_event_count['phishing'] += 1
                elif event_id in [event['id'] for event in ransomware_events]:
                    tag_event(event_id, RANSOMWARE_TAGS[0], headers)
                    event_tags.append(RANSOMWARE_TAGS[0])
                    tagged_event_count['ransomware'] += 1
                elif event_id in [event['id'] for event in both_events]:
                    # Tag with both phishing and ransomware tags
                    tag_event(event_id, PHISHING_TAGS[0], headers)
                    tag_event(event_id, RANSOMWARE_TAGS[0], headers)
                    event_tags.extend([PHISHING_TAGS[0], RANSOMWARE_TAGS[0]])
                    tagged_event_count['phishing'] += 1
                    tagged_event_count['ransomware'] += 1
                
                # Write tagged event to the CSV
                tagged_writer.writerow([idx, event_id, ', '.join(event_tags)])
                tagged_event_count['total'] += 1

        # Open CSV for writing fetched IOCs
        with open(iocs_csv_file_path, mode='w', newline='', encoding='utf-8') as file:
            ioc_writer = csv.writer(file)
            ioc_writer.writerow(["Sr. No.", "Event ID", "Event Info", "url", "domain", "ip-src", "ip-dst", "file_hashes", "email-src", "email-dst", "email-attachment", "regkey", "btc", "xmr", "eth"])

            # Fetch and write IOCs for the selected events
            for idx, event_id in enumerate(selected_event_ids, 1):    
                iocs = fetch_event_iocs(event_id)
                if iocs:
                    event_info = next(event['info'] for event in phishing_events + ransomware_events + both_events if event['id'] == event_id)
                    ioc_writer.writerow([
                        idx, event_id, event_info,
                        ", ".join(iocs.get('url', [])),
                        ", ".join(iocs.get('domain', [])),
                        ", ".join(iocs.get('ip-src', [])),
                        ", ".join(iocs.get('ip-dst', [])),
                        ", ".join([str(h) for h in iocs.get('file_hashes', [])]),
                        ", ".join(iocs.get('email-src', [])),
                        ", ".join(iocs.get('email-dst', [])),
                        ", ".join(iocs.get('email-attachment', [])),
                        ", ".join(iocs.get('regkey', [])),
                        ", ".join(iocs.get('btc', [])),
                        ", ".join(iocs.get('xmr', [])),
                        ", ".join(iocs.get('eth', []))
                    ])

        logging.info(f"Tagged events: {tagged_event_count}")
        logging.info(f"IOCs for selected events saved to {iocs_csv_file_path}")
        return render_template('download_csv.html', tagged_event_count=tagged_event_count)

    except Exception as e:
        logging.error(f"Error saving IOCs to CSV: {e}")
        flash(f"Error saving IOCs to CSV: {e}", "danger")
        return redirect(url_for('fetch_both'))
    
# Function to fetch IOCs for selected events and save to CSV
def fetch_event_iocs(event_id):
    headers = {
        'Authorization': misp_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    url = f"{misp_url}/events/{event_id}"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        event_data = response.json().get('Event', {})
        return extract_iocs(event_data)
    else:
        logging.info(f"Failed to fetch IOCs for event {event_id}", "danger")
        return None

# Function to extract IOCs
def extract_iocs(event_data):
    attributes = event_data.get("Attribute", [])
    extracted_iocs = {
        "url": [],
        "domain": [],
        "ip-src": [],
        "ip-dst": [],
        "file_hashes": [],
        "email-src": [],
        "email-attachment": [],
        "regkey": [],
        "btc": [],
        "xmr": [],
        "eth": []
    }

    for attribute in attributes:
        attr_type = attribute.get("type")
        attr_value = attribute.get("value")

        if attr_type == "url":
            extracted_iocs["url"].append(attr_value)
        elif attr_type == "domain":
            extracted_iocs["domain"].append(attr_value)
        elif attr_type == "ip-src":
            extracted_iocs["ip-src"].append(attr_value)
        elif attr_type == "ip-dst":
            extracted_iocs["ip-dst"].append(attr_value)
        elif attr_type in ["md5", "sha1", "sha256"]:
            extracted_iocs["file_hashes"].append({attr_type: attr_value})
        elif attr_type == "email-src":
            extracted_iocs["email-src"].append(attr_value)
        elif attr_type == "email-attachment":
            extracted_iocs["email-attachment"].append(attr_value)
        elif attr_type == "regkey":
            extracted_iocs["regkey"].append(attr_value)
        elif attr_type == "btc":
            extracted_iocs["btc"].append(attr_value)
        elif attr_type == "xmr":
            extracted_iocs["xmr"].append(attr_value)
        elif attr_type == "eth":
            extracted_iocs["eth"].append(attr_value)

    # If 'email-dst' is not present in event data, ensure it is initialized
    if 'email-dst' not in extracted_iocs:
        extracted_iocs['email-dst'] = []

    return extracted_iocs

# Route to download the CSV file
@app.route('/download_csv', methods=['GET'])
def download_csv():
    # Path to the saved CSV file
    try:
        if os.path.exists(iocs_csv_file_path):
            return send_file(iocs_csv_file_path, as_attachment=True)
        else:
            logging.info("CSV file not found. Please fetch IOCs first.", "danger")
            return redirect(url_for('fetch_both'))
    except Exception as e:
        logging.info(f"Error downloading CSV: {e}", "danger")
        return redirect(url_for('fetch_both'))

# Route to download the tagged events CSV
@app.route('/download_tagged_events_csv', methods=['GET'])
def download_tagged_events_csv():
    try:
        # Ensure the file exists before sending it
        if os.path.exists(tagged_csv_file_path):
            return send_file(tagged_csv_file_path, as_attachment=True)
        else:
            logging.error("Tagged events CSV file not found.")
            flash("Tagged events CSV file not found.", "danger")
            return redirect(url_for('fetch_both'))
    except Exception as e:
        logging.error(f"Error downloading tagged events CSV: {e}")
        flash(f"Error downloading tagged events CSV: {e}", "danger")
        return redirect(url_for('fetch_both'))
    

def get_graph_token():
    global microsoft_graph_token, microsoft_graph_headers, token_expiration_time
    global graph_client_id, graph_client_secret, graph_tenant_id  # Ensure global access to credentials

    if not all([graph_client_id, graph_client_secret, graph_tenant_id]):
        logging.error("Graph API credentials are not set.")
        return

    try:
        authority = f"https://login.microsoftonline.com/{graph_tenant_id}"
        app = ConfidentialClientApplication(
            client_id=graph_client_id,
            client_credential=graph_client_secret,
            authority=authority
        )
        token = app.acquire_token_for_client(scopes=graph_scope)

        if "access_token" in token:
            microsoft_graph_token = token["access_token"]
            expires_in = token.get("expires_in", 3600)  # Default to 1 hour if no expiration time is provided
            token_expiration_time = time.time() + expires_in  # Set the expiration time
            
            microsoft_graph_headers = {
                "Authorization": f"Bearer {microsoft_graph_token}",
                "Content-Type": "application/json"
            }
            logging.info("Successfully authenticated with Microsoft Graph API.")
        else:
            logging.error("Failed to authenticate with Microsoft Graph API.")
    except Exception as e:
        logging.error(f"Error during authentication: {e}")

def ensure_valid_token():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    # Use the MSAL Confidential Client Application to silently acquire a token
    app_confidential = ConfidentialClientApplication(CLIENT_ID, client_credential=CLIENT_SECRET, authority=AUTHORITY)

    accounts = app_confidential.get_accounts()
    if accounts:
        result = app_confidential.acquire_token_silent(scopes=SCOPE, account=accounts[0])
        if 'access_token' in result:
            session['access_token'] = result['access_token']
        else:
            # If token refresh fails, redirect to login
            return redirect(url_for('login'))

@app.route('/add_microsoft_graph_creds', methods=['GET', 'POST'])
def add_microsoft_graph_creds():
    if request.method == 'POST':
        # Extract form data
        client_id = request.form.get('graph_client_id')
        client_secret = request.form.get('graph_client_secret')
        tenant_id = request.form.get('graph_tenant_id')

        # Update global credentials
        global graph_client_id, graph_client_secret, graph_tenant_id
        graph_client_id = client_id
        graph_client_secret = client_secret
        graph_tenant_id = tenant_id

        # Call the function to get the Microsoft Graph token
        get_graph_token()

        # Redirect to the page where the user can start/stop phishing email checks
        return redirect(url_for('email_monitoring_options'))

    return render_template('add_microsoft_graph_creds.html')

@app.route('/login')
def login():
    # Create an MSAL Confidential Client Application
    app_confidential = ConfidentialClientApplication(CLIENT_ID, client_credential=CLIENT_SECRET, authority=AUTHORITY)
    
    # Get the authorization URL
    auth_url = app_confidential.get_authorization_request_url(SCOPE, redirect_uri=REDIRECT_URI)
    
    # Redirect the user to Microsoft's login page
    return redirect(auth_url)

@app.route('/callback')
def callback():
    global stored_access_token
    # Get the authorization code from the request
    code = request.args.get('code')
    
    # Create an MSAL Confidential Client Application
    app_confidential = ConfidentialClientApplication(CLIENT_ID, client_credential=CLIENT_SECRET, authority=AUTHORITY)
    
    # Acquire token using the authorization code
    result = app_confidential.acquire_token_by_authorization_code(code, scopes=SCOPE, redirect_uri=REDIRECT_URI)
    
    # If the token was successfully acquired, store it in a global variable
    if 'access_token' in result:
        stored_access_token = result['access_token']
        logging.info(f"Access Token is - {stored_access_token}")
        return redirect(url_for('email_monitoring_options'))
    else:
        return f"Error during authentication: {result.get('error_description')}", 400

# Email monitoring options page
@app.route('/email_monitoring_options', methods=['GET'])
def email_monitoring_options():
    if 'access_token' not in session:
        return redirect(url_for('login'))
    return render_template('email_monitoring_options.html')

@app.route('/start_email_check', methods=['GET'])
def start_email_check():
    try:
        job = scheduler.get_job('email_check')
        if job:
            logging.info('Email monitoring is already running.', 'info')
        else:
            scheduler.add_job(check_emails, trigger="interval", minutes=1, id="email_check")
            logging.info("Email monitoring started. Checking every 1 minute for phishing emails.", "success")
    except Exception as e:
        logging.error(f"Error starting email monitoring: {e}")
        logging.error("Failed to start email monitoring.", "danger")
    
    return redirect(url_for('email_monitoring_options'))

# Check for unread emails
# Scheduled function to check emails using the stored token
def check_emails():
    global stored_access_token
    
    if not stored_access_token:
        logging.error("Access token not available. Cannot check emails.")
        return

    # Set headers with the stored access token
    headers = {
        'Authorization': f"Bearer {stored_access_token}",
        'Content-Type': 'application/json'
    }

    logging.info(f"Checking phishing emails for user ID.")
    folders = ["inbox", "sentitems"]

    for folder in folders:
        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?$top=10&$filter=isRead eq false"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            emails = response.json().get('value', [])
            logging.info(f"Found {len(emails)} unread emails in {folder}")
            for email in emails:
                email_id = email.get("id")
                process_email(email, email_id)
        else:
            logging.error(f"Error fetching unread emails from {folder}: {response.text}")

    # Use /me endpoint to fetch unread emails from the inbox
    #response = requests.get("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=10&$filter=isRead eq false", headers=headers)
    
    #if response.status_code == 200:
    #    emails = response.json().get('value', [])
    #    logging.info(f"Unread emails: {emails}")
    #else:
    #    logging.error(f"Error fetching emails: {response.text}")


#def check_phishing_emails():
    #ensure_valid_token()  # Ensure token is valid before making requests
    
    #user_id = get_user_id("raksbens@outlook.com")  # Use the actual user's email
    #if not user_id:
        #logging.error("User ID is None. Cannot proceed with email check.")
        #return

#    logging.info(f"Checking phishing emails for user ID.")
#    folders = ["inbox", "sentitems"]
#
#    for folder in folders:
#        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?$top=10&$filter=isRead eq false"
#        response = requests.get(url, headers=microsoft_graph_headers)

#        if response.status_code == 200:
#            emails = response.json().get('value', [])
#            logging.info(f"Found {len(emails)} unread emails in {folder}")
#            for email in emails:
#                email_id = email.get("id")
#                process_email(email, email_id)
#        else:
#            logging.error(f"Error fetching unread emails from {folder}: {response.text}")


# Function to move email to phishing folder
def move_email_to_phishing(email_id):
    global stored_access_token
    
    if not stored_access_token:
        logging.error("Access token not available. Cannot move emails.")
        return

    headers = {
        'Authorization': f"Bearer {stored_access_token}",
        'Content-Type': 'application/json'
    }

    # Get the phishing folder ID
    phishing_folder_id = get_phishing_folder_id(headers)
    if not phishing_folder_id:
        logging.error("Could not retrieve phishing folder ID.")
        return

    # Move the email to the phishing folder
    move_url = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}/move"
    data = {"destinationId": phishing_folder_id}

    response = requests.post(move_url, headers=headers, json=data)
    if response.status_code == 200:
        logging.info(f"Email {email_id} moved to the phishing folder successfully.")
    else:
        logging.error(f"Failed to move email {email_id} to phishing folder: {response.text}")

            
def process_email(email, email_id):
    subject = email.get("subject", "No Subject")
    body = email.get("bodyPreview", "")
    attachments = email.get("hasAttachments", False)
    
    logging.info(f"Processing email with subject: {subject}")
    
    if check_email_against_iocs(subject, body, attachments, email_id) == True:
        move_email_to_phishing(email_id)
    else:
        logging.info(f"Email does not appear to be phishing: {subject}")


import shutil

# Function to calculate hash and delete attachment after hashing
def calculate_hash(file_path):
    logging.debug(f"Calculating hash for file: {file_path}")
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except OSError as e:
        logging.error(f"Failed to open file {file_path} for hashing: {e}")
        return None

    hash_value = sha256_hash.hexdigest()
    logging.debug(f"Calculated SHA256 hash for {file_path}: {hash_value}")

    # Delete the file after hashing
    try:
        os.remove(file_path)
        logging.debug(f"Deleted attachment file: {file_path}")
    except OSError as e:
        logging.error(f"Failed to delete file {file_path}: {e}")

    return hash_value

# Function to check email against IOCs and move it if phishing is detected
def check_email_against_iocs(subject, body, attachments, email_id):
    iocs_to_check = load_iocs_from_csv()
    match_score = 0
    threshold = 1  # Define the threshold for phishing detection

    # Check URLs in the email body
    for url in iocs_to_check['url']:
        if url in body:
            match_score += 1
            logging.warning(f"Phishing URL detected in email: {url}")

    # Check domains in the email body
    for domain in iocs_to_check['domain']:
        if domain in body:
            match_score += 1
            logging.warning(f"Phishing domain detected in email: {domain}")

    # Check attachments for hashes
    if attachments:
        downloaded_attachments = download_email_attachments(email_id)
        for attachment in downloaded_attachments:
            file_hash = calculate_hash(attachment)
            if file_hash in iocs_to_check['file_hashes']:
                match_score += 1
                logging.warning(f"Phishing attachment detected: {file_hash}")

    # Move the email to the phishing folder if the match score meets or exceeds the threshold
    if match_score >= threshold:
        move_email_to_phishing(email_id)
        return True

    return False

# Function to get the phishing folder ID
def get_phishing_folder_id(headers):
    folder_url = "https://graph.microsoft.com/v1.0/me/mailFolders"
    response = requests.get(folder_url, headers=headers)

    if response.status_code == 200:
        folders = response.json().get('value', [])
        for folder in folders:
            if folder.get('displayName', '').lower() == 'phishing':
                return folder.get('id')
        
        # If the phishing folder does not exist, create one
        return create_phishing_folder(headers)
    else:
        logging.error(f"Error retrieving mail folders: {response.text}")
        return None

# Function to create a phishing folder if it doesn't exist
def create_phishing_folder(headers):
    create_folder_url = "https://graph.microsoft.com/v1.0/me/mailFolders"
    data = {
        "displayName": "Phishing"
    }

    response = requests.post(create_folder_url, headers=headers, json=data)
    if response.status_code == 201:
        folder_id = response.json().get('id')
        logging.info(f"Phishing folder created with ID: {folder_id}")
        return folder_id
    else:
        logging.error(f"Failed to create phishing folder: {response.text}")
        return None

def load_iocs_from_csv():
    iocs = {'url': [], 'domain': [], 'file_hashes': []}
    
    if os.path.exists(iocs_csv_file_path):
        with open(iocs_csv_file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                iocs['url'].extend(row['url'].split(", "))
                iocs['domain'].extend(row['domain'].split(", "))
                iocs['file_hashes'].extend(row['file_hashes'].split(", "))
    
    logging.debug(f"Loaded {len(iocs['url'])} URLs, {len(iocs['domain'])} domains, and {len(iocs['file_hashes'])} file hashes from IOC CSV.")
    return iocs

def download_email_attachments(email_id):
    global stored_access_token
    
    if not stored_access_token:
        logging.error("Access token not available. Cannot check emails.")
        return

    # Set headers with the stored access token
    headers = {
        'Authorization': f"Bearer {stored_access_token}",
        'Content-Type': 'application/json'
    }

    attachments = []
    url = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}/attachments"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        attachment_data = response.json().get('value', [])
        for attachment in attachment_data:
            if attachment.get('@odata.type') == '#microsoft.graph.fileAttachment':
                attachment_content = base64.b64decode(attachment['contentBytes'])
                file_name = attachment['name']
                attachment_path = os.path.join(TEMP_ATTACHMENT_DIR, file_name)
                with open(attachment_path, 'wb') as f:
                    f.write(attachment_content)
                attachments.append(attachment_path)
                logging.debug(f"Downloaded attachment: {file_name}")
    
    return attachments

def delete_email(email_id):
    global stored_access_token
    
    if not stored_access_token:
        logging.error("Access token not available. Cannot check emails.")
        return

    # Set headers with the stored access token
    headers = {
        'Authorization': f"Bearer {stored_access_token}",
        'Content-Type': 'application/json'
    }
    url = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}"
    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        logging.info(f"Phishing email deleted: {email_id}")
    else:
        logging.error(f"Failed to delete phishing email: {email_id}. Error: {response.text}")

#@app.route('/status_page', methods=['GET'])
#def status_page():
#    monitoring_status = "running" if is_email_monitoring_running() else "stopped"
#    return render_template('status_page.html', monitoring_status=monitoring_status)

#def is_email_monitoring_running():
    #job = scheduler.get_job('email_check')
    #return job is not None

#def get_user_id(email):
    #url = f"https://graph.microsoft.com/v1.0/users/{email}"
    #response = requests.get(url, headers=microsoft_graph_headers)
    #if response.status_code == 200:
    #    user_id = response.json().get('id')
    #    logging.info(f"Fetched user ID for {email}: {user_id}")
    #    return user_id
    #else:
    #    logging.error(f"Error fetching user ID for {email}: {response.text}")
    #    return None    

@app.route('/stop_email_check', methods=['GET'])
def stop_email_check():
    try:
        scheduler.remove_job("email_check")
        logging.info("Stopped email monitoring.", "success")
    except Exception as e:
        logging.error(f"Error stopping email monitoring: {e}")
        logging.error("No active email monitoring job was found.", "danger")
    return redirect(url_for('email_monitoring_options'))


    
# Route to add Shuffle credentials
@app.route('/add_shuffle_credentials', methods=['GET', 'POST'])
def add_shuffle_credentials():
    global shuffle_url, shuffle_api_key

    if request.method == 'POST':
        shuffle_url = request.form.get('shuffle_url')
        shuffle_api_key = request.form.get('shuffle_api_key')

        if shuffle_url and shuffle_api_key:
            logging.info('Shuffle credentials saved successfully!', 'success')
            return redirect(url_for('shuffle_options'))  # Redirect to Shuffle actions page
        else:
            logging.info('Please provide both Shuffle URL and API key.', 'danger')

    return render_template('add_shuffle_credentials.html')

# Route to present the Shuffle options (fetch or create workflow)
@app.route('/shuffle_options', methods=['GET'])
def shuffle_options():
    if not shuffle_url or not shuffle_api_key:
        logging.info("Please add Shuffle credentials first!", "danger")
        return redirect(url_for('add_shuffle_credentials'))
    
    return render_template('shuffle_options.html')

def shuffle_request(endpoint, method="GET", data=None):
    headers = {
        "Authorization": f"Bearer {shuffle_api_key}",
        "Content-Type": "application/json"
    }
    url = f"{shuffle_url}/api/v1{endpoint}"

    print(f"Making {method} request to {url} with headers: {headers} and data: {data}")  # Debugging message

    try:
        # Make the appropriate request based on the method
        if method == "POST":
            response = requests.post(url, json=data, headers=headers, verify=False)
        elif method == "GET":
            response = requests.get(url, headers=headers, verify=False)

        # Check for successful response
        if response.status_code in [200, 201]:
            print(f"Response: {response.json()}")  # Debugging message
            return response.json()  # Return the JSON response
        else:
            print(f"Error: {response.text}")  # Debugging message
            logging.info(f"Shuffle API error: {response.text}", "danger")
            return None
    except Exception as e:
        print(f"Exception: {e}")  # Debugging message
        logging.info(f"Error connecting to Shuffle API: {e}", "danger")
        return None

@app.route('/fetch_existing_workflows', methods=['GET'])
def fetch_existing_workflows():
    if not shuffle_api_key or not shuffle_url:
        logging.info("Please configure Shuffle API details first!", "danger")
        return redirect(url_for('add_shuffle_credentials'))

    # Debugging message to verify this route is being called
    print("Fetching existing workflows...")

    # Fetch existing workflows using Shuffle API
    response = shuffle_request('/workflows', method='GET')

    if response:
        print(f"Workflows fetched: {response}")  # Debugging message to verify response
        workflows = response  # JSON response containing workflow information
        return render_template('existing_workflows.html', workflows=workflows)
    else:
        print("Failed to fetch workflows from Shuffle.")  # Debugging message
        logging.error('Failed to fetch workflows from Shuffle.', 'danger')
        return redirect(url_for('shuffle_options'))

# Route to create a new workflow in Shuffle based on IOCs
@app.route('/create_new_workflow', methods=['GET', 'POST'])
def create_new_workflow():
    if not shuffle_api_key or not shuffle_url:
        logging.error("Please configure Shuffle API details first!", "danger")
        return redirect(url_for('add_shuffle_credentials'))

    if request.method == 'POST':
        workflow_name = request.form.get('workflow_name')
        description = request.form.get('description')

        if not workflow_name or not description:
            logging.error("Workflow name and description are required.", "danger")
            return redirect(url_for('create_new_workflow'))

        # Prepare data for the new workflow
        workflow_data = {
            "name": workflow_name,
            "description": description,
            "enabled": True
        }

        # Create the workflow in Shuffle using the API
        response = shuffle_request('/workflows', method="POST", data=workflow_data)

        if response:
            logging.info(f'Workflow "{workflow_name}" created successfully!', 'success')
            return redirect(url_for('fetch_existing_workflows'))
        else:
            logging.error("Failed to create workflow in Shuffle.", "danger")

    return render_template('create_workflow.html')

@app.route('/trigger_workflow/<workflow_id>', methods=['POST', 'GET'])
def trigger_workflow(workflow_id):
    # Check if Shuffle API details are set
    if not shuffle_api_key or not shuffle_url:
        logging.error("Please configure Shuffle API details first!", "danger")
        return redirect(url_for('add_shuffle_credentials'))

    # Make the API request to trigger the workflow
    response = shuffle_request(f'/workflows/{workflow_id}/run', method='POST')

    if response:
        logging.info(f"Workflow {workflow_id} triggered successfully!", "success")
    else:
        logging.error(f"Failed to trigger workflow {workflow_id}.", "danger")
    
    # Redirect back to the list of existing workflows
    return redirect(url_for('fetch_existing_workflows'))



if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True, port=9000, use_reloader=True)
