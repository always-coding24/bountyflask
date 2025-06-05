#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests
import time
import hashlib
import threading
import random
import json
import datetime
import os
from requests.exceptions import RequestException
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─── Configuration Defaults ─────────────────────────────────────────────────────
LOGIN_URL           = "https://www.bounty-news.com/api/member/login"
PAGE_URL            = "https://www.bounty-news.com/api/worksInfo/page"
HISTORY_URL         = "https://www.bounty-news.com/api/worksHistory/pageHistory"
CONTENT_URL         = "https://www.bounty-news.com/api/worksInfoContent/getContent"
START_READ_URL      = "https://www.bounty-news.com/api/worksInfo/startRead"
CLAIM_URL           = "https://www.bounty-news.com/api/worksInfo/claimReward"
DAILY_INFO_URL      = "https://www.bounty-news.com/api/memberReadingReward/info"
DAILY_AWARD_URL     = "https://www.bounty-news.com/api/memberReadingReward/getAward"

SALES_PERSON_ID = "232"
LANGUAGE        = "en_US"
USER_SYSTEM     = "android 11"
USER_DEVICE     = "firefox/128.0"

CATEGORY_ID   = "1921117247997878274"
PAGE_SIZE     = 10
MAX_PAGES     = 30
DELAY_SECONDS = 32
MAX_READS     = 50

# Retry configuration
MAX_RETRIES = 5
RETRY_DELAY_BASE = 5  # Base delay in seconds
RETRY_DELAY_MAX = 30  # Maximum delay in seconds

# Global variables for app state
running_jobs = {}  # Track running jobs by job_id
job_logs = {}      # Store logs for each job
all_credentials = []  # Will store credentials from file

# Load credentials from file
def load_credentials():
    try:
        if os.path.exists('credentials.json'):
            with open('credentials.json', 'r') as f:
                return json.load(f)
        else:
            # Default credentials
            return [
             {"phone": "09582811870", "code": "755"},
    {"phone": "09291078442", "code": "586"},
    {"phone": "09497941608", "code": "964"},
    {"phone": "09344474585", "code": "922"},
    {"phone": "09465307245", "code": "715"},
    {"phone": "09137520214", "code": "872"},
    {"phone": "09170363921", "code": "521"},
    {"phone": "09258785549", "code": "835"},
    {"phone": "09554072913", "code": "602"},
    {"phone": "09220359954", "code": "609"},
    {"phone": "09489110740", "code": "638"},
    {"phone": "09194589054", "code": "254"},
    {"phone": "09137666532", "code": "993"},
    {"phone": "09248750308", "code": "298"},
    {"phone": "09506615700", "code": "399"},
    {"phone": "09362605643", "code": "794"},
    {"phone": "09494997709", "code": "700"},
    {"phone": "09546494096", "code": "767"},
    {"phone": "09154011245", "code": "395"},
    {"phone": "09200451732", "code": "729"},
    {"phone": "09470493591", "code": "820"},
    {"phone": "09267209118", "code": "825"},
    {"phone": "09363840678", "code": "877"},
    {"phone": "09523781152", "code": "395"},
    {"phone": "09457865133", "code": "855"},
    {"phone": "09217197100", "code": "443"},
    {"phone": "09103198637", "code": "473"},
    {"phone": "09276897178", "code": "408"},
    {"phone": "09475319134", "code": "376"},
    {"phone": "09404418585", "code": "162"},
    {"phone": "09325562525", "code": "258"},
    {"phone": "09208981743", "code": "344"},
    {"phone": "09507874412", "code": "726"},
    {"phone": "09341058232", "code": "868"},
    {"phone": "09381108034", "code": "801"},
    {"phone": "09498165386", "code": "654"},
    {"phone": "09311290235", "code": "297"},
    {"phone": "09175596662", "code": "638"},
    {"phone": "09270872633", "code": "411"},
    {"phone": "09278534509", "code": "791"},
    {"phone": "09568868916", "code": "965"},
    {"phone": "09456985513", "code": "644"},
    {"phone": "09343432491", "code": "293"},
    {"phone": "09517723306", "code": "504"},
    {"phone": "09176891014", "code": "501"},
    {"phone": "09202974667", "code": "336"},
    {"phone": "09177568570", "code": "242"},
    {"phone": "09198389703", "code": "673"},
    {"phone": "09210478623", "code": "354"},
    {"phone": "09497128182", "code": "351"},
            ]
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return []

# Save credentials to file
def save_credentials(credentials):
    with open('credentials.json', 'w') as f:
        json.dump(credentials, f, indent=2)

# Initialize credentials
all_credentials = load_credentials()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Custom logger that stores logs for web display
class WebLogger:
    def __init__(self, job_id):
        self.job_id = job_id
        job_logs[job_id] = []
    
    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        print(formatted_msg)
        job_logs[self.job_id].append(formatted_msg)
        
    def get_logs(self):
        return job_logs.get(self.job_id, [])

# ─── Session Setup ─────────────────────────────────────────────────────────────
def setup_session():
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json",
        "language": LANGUAGE,
        "X-User-System": USER_SYSTEM,
        "X-User-Device-Type": USER_DEVICE,
        "User-Agent": "Mozilla/5.0 Firefox/128.0"
    })
    return s

# ─── Compute MD5 hash ───────────────────────────────────────────────────────────
def make_hash(raw_password: str) -> str:
    return hashlib.md5(raw_password.encode()).hexdigest()

# ─── Enhanced HTTP Request with Retry Logic ───────────────────────────────────────
def make_request_with_retry(session, method, url, json_data=None, phone="Unknown", operation="", logger=None):
    """
    Make HTTP request with retry logic for handling temporary failures.
    
    Args:
        session: requests.Session object
        method: 'get' or 'post'
        url: URL to request
        json_data: JSON payload for POST requests
        phone: Phone number (for logging)
        operation: What operation is being performed (for logging)
        logger: WebLogger instance
        
    Returns:
        Response JSON object if successful
        
    Raises:
        RuntimeError if all retries fail
    """
    retries = 0
    last_error = None
    
    while retries <= MAX_RETRIES:
        try:
            if method.lower() == 'get':
                response = session.get(url)
            else:  # post
                response = session.post(url, json=json_data)
            
            # Check for HTTP errors
            if response.status_code >= 500:
                raise RequestException(f"Server error: HTTP {response.status_code}")
                
            # Try to parse JSON (may raise ValueError)
            data = response.json()
            
            # Log success
            if retries > 0:
                log_msg = f"[{phone}] ✅ {operation} succeeded after {retries} retries"
                if logger:
                    logger.log(log_msg)
                
            return data
            
        except (RequestException, ValueError, ConnectionError) as e:
            last_error = e
            retries += 1
            
            if retries > MAX_RETRIES:
                break
                
            # Calculate backoff delay with jitter
            delay = min(RETRY_DELAY_BASE * (2 ** (retries - 1)) + random.uniform(0, 1), RETRY_DELAY_MAX)
            log_msg = f"[{phone}] ⚠️ {operation} failed (attempt {retries}/{MAX_RETRIES}): {str(e)}. Retrying in {delay:.1f}s..."
            if logger:
                logger.log(log_msg)
            time.sleep(delay)
    
    # If we get here, all retries failed
    raise RuntimeError(f"{operation} failed after {MAX_RETRIES} attempts: {str(last_error)}")

# ─── Fetch reading history ─────────────────────────────────────────────────────
def get_read_history(session, phone, logger):
    """
    Fetch all pages from worksHistory/pageHistory.
    Return a set of worksInfoId strings already read.
    """
    read_ids = set()
    page_no = 1
    
    while True:
        payload = {"pageNo": page_no, "pageSize": 50}
        try:
            data = make_request_with_retry(
                session, 'post', HISTORY_URL, payload, 
                phone=phone, operation=f"fetch history page {page_no}",
                logger=logger
            )
            
            if not data.get("success"):
                break
                
            for entry in data["result"]["list"]:
                read_ids.add(entry["worksInfoId"])
                
            if data["result"].get("isLastPage"):
                break
                
            page_no += 1
            
        except Exception as e:
            logger.log(f"[{phone}] ⚠️ Error fetching history page {page_no}: {e}")
            break
            
    return read_ids

# ─── Fetch content ID ───────────────────────────────────────────────────────────
def fetch_content_id(session, works_info_id, phone, logger):
    """
    Call getContent to retrieve worksInfoContentId for a given worksInfoId.
    Returns content_id string or None if not found.
    """
    try:
        data = make_request_with_retry(
            session, 'post', CONTENT_URL, {"id": works_info_id}, 
            phone=phone, operation=f"fetch content for {works_info_id}",
            logger=logger
        )
        
        if not data.get("success") or not data.get("result"):
            return None
            
        return data["result"][0]["id"]
        
    except Exception as e:
        logger.log(f"[{phone}] ⚠️ Error fetching content ID for {works_info_id}: {e}")
        return None

# ─── Core Functions ─────────────────────────────────────────────────────────────
def login(session, phone, code, logger):
    raw = f"password{code}"
    pw_hash = make_hash(raw)
    logger.log(f"[{phone}] Using password hash: {pw_hash}")
    
    try:
        data = make_request_with_retry(
            session, 'post', LOGIN_URL, {"phone": phone, "password": pw_hash}, 
            phone=phone, operation="login",
            logger=logger
        )
        
        if not data.get("success"):
            raise RuntimeError(f"Login failed: {data.get('message')}")
            
        tok = data["result"]["token"]
        head = data["result"]["tokenHead"]
        auth = f"{head} {tok}"
        session.headers.update({
            "Authorization": auth,
            "memberInfoId": data["result"]["sysUserId"],
            "salesPersonId": SALES_PERSON_ID
        })
        logger.log(f"[{phone}] ✔ Logged in")
        
    except Exception as e:
        logger.log(f"[{phone}] 🚨 Login error: {e}")
        raise

def fetch_article_ids(session, phone, logger):
    """
    Grab up to MAX_READS worksInfoId values by paging through first MAX_PAGES.
    """
    ids = []
    
    for page in range(1, MAX_PAGES + 1):
        try:
            data = make_request_with_retry(
                session, 'post', PAGE_URL, 
                {
                    "pageNo": page,
                    "pageSize": PAGE_SIZE,
                    "categoryId": CATEGORY_ID
                }, 
                phone=phone, operation=f"fetch page {page}",
                logger=logger
            )
            
            if not data.get("success"):
                logger.log(f"[{phone}] ⚠️ Failed to fetch page {page}")
                continue
                
            for item in data["result"]["list"]:
                if len(ids) >= MAX_READS:
                    break
                ids.append(item["id"])
                
            if len(ids) >= MAX_READS:
                break
                
        except Exception as e:
            logger.log(f"[{phone}] ⚠️ Error fetching page {page}: {e}")
            continue
            
    return ids

def claim_daily_rewards(session, phone, logger):
    """Claim daily tier rewards with retry logic"""
    logger.log(f"[{phone}] 🔄 Claiming daily tier rewards...")
    
    try:
        resp = make_request_with_retry(
            session, 'post', DAILY_INFO_URL, {}, 
            phone=phone, operation="fetch daily rewards info",
            logger=logger
        )
        
        if not resp.get("success"):
            logger.log(f"[{phone}] ❌ Failed to fetch daily rewards info")
            return
            
        for tier in resp["result"]["memberReadingRewardDetailVoList"]:
            if tier.get("memberReadingRewardStatus") == "complete":
                num = tier.get("workInfoReadingNum")
                try:
                    r = make_request_with_retry(
                        session, 'post', DAILY_AWARD_URL, 
                        {"workInfoReadingNum": num}, 
                        phone=phone, operation=f"claim daily bonus for {num} articles",
                        logger=logger
                    )
                    
                    if r.get("success"):
                        logger.log(f"[{phone}] 🎁 Daily bonus for {num} articles claimed")
                    else:
                        logger.log(f"[{phone}] ⚠️ Daily bonus claim for {num} failed: {r.get('message')}")
                        
                except Exception as e:
                    logger.log(f"[{phone}] ⚠️ Error claiming daily bonus for {num} articles: {e}")
                    
    except Exception as e:
        logger.log(f"[{phone}] ❌ Error with daily rewards: {e}")

def run_for_user(cred, job_id, should_stop):
    logger = WebLogger(job_id)
    session = setup_session()
    phone = cred["phone"]
    code = cred["code"]
    
    logger.log(f"Starting process for user {phone}")

    try:
        # Check if we should stop
        if should_stop():
            logger.log(f"[{phone}] Process stopped by user")
            return

        # 1) Login
        login(session, phone, code, logger)

        # Check if we should stop
        if should_stop():
            logger.log(f"[{phone}] Process stopped by user after login")
            return

        # 2) Fetch reading history
        logger.log(f"[{phone}] Fetching reading history...")
        history_ids = get_read_history(session, phone, logger)
        logger.log(f"[{phone}] {len(history_ids)} articles already read")

        # Check if we should stop
        if should_stop():
            logger.log(f"[{phone}] Process stopped by user after fetching history")
            return

        # 3) Fetch article IDs
        article_ids = fetch_article_ids(session, phone, logger)
        if not article_ids:
            logger.log(f"[{phone}] No articles found")
            return

        # 4) Process each ID if not in history
        claimed = 0
        for works_id in article_ids:
            # Check if we should stop
            if should_stop():
                logger.log(f"[{phone}] Process stopped by user during article processing")
                return
                
            if works_id in history_ids:
                logger.log(f"[{phone}] ⏭️ {works_id} already read, skipping")
                continue

            # a) Fetch content ID for this worksInfoId
            content_id = fetch_content_id(session, works_id, phone, logger)
            if not content_id:
                logger.log(f"[{phone}] ⚠️ No content for {works_id}, skipping")
                continue

            # b) startRead
            try:
                sr_data = make_request_with_retry(
                    session, 'post', START_READ_URL, 
                    {
                        "worksInfoContentId": content_id,
                        "worksInfoId": works_id
                    }, 
                    phone=phone, operation=f"startRead({works_id})",
                    logger=logger
                )
                
                logger.log(f"[{phone}] startRead({works_id}) → {sr_data}")

                # If server says AlreadyRead (businessMessage or code 1021), skip claim
                if not sr_data.get("success") and (
                    sr_data.get("businessMessage") == "AlreadyRead" or sr_data.get("code") == 1021
                ):
                    logger.log(f"[{phone}] ⏭️ {works_id} marked AlreadyRead by server, skipping claim")
                    continue
                    
            except Exception as e:
                logger.log(f"[{phone}] ⚠️ Error in startRead for {works_id}: {e}")
                continue

            # c) Wait DELAY_SECONDS
            logger.log(f"[{phone}] Waiting {DELAY_SECONDS}s before claiming {works_id}...")
            
            # Wait with check for stop
            for _ in range(DELAY_SECONDS):
                if should_stop():
                    logger.log(f"[{phone}] Process stopped by user during waiting period")
                    return
                time.sleep(1)

            # d) claimReward
            try:
                cr_data = make_request_with_retry(
                    session, 'post', CLAIM_URL, 
                    {"worksInfoContentId": content_id}, 
                    phone=phone, operation=f"claimReward({works_id})",
                    logger=logger
                )

                if cr_data.get("success"):
                    logger.log(f"[{phone}] 🎉 Claimed reward for {works_id}")
                    claimed += 1
                else:
                    logger.log(f"[{phone}] ❌ claimReward({works_id}) failed: {cr_data}")
                    
            except Exception as e:
                logger.log(f"[{phone}] ❌ Error claiming reward for {works_id}: {e}")

            if claimed >= MAX_READS:
                break

        logger.log(f"[{phone}] {claimed}/{len(article_ids)} rewards claimed")

        # 5) Claim daily tier rewards
        if not should_stop():
            claim_daily_rewards(session, phone, logger)

        logger.log(f"[{phone}] ✅ Done\n")

    except Exception as e:
        logger.log(f"[{phone}] 🚨 Error: {e}\n")

# Flask routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', 
                          credentials=all_credentials, 
                          running_jobs=running_jobs,
                          job_logs=job_logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simple authentication - in production, use secure authentication
        if username == 'admin' and password == 'bounty123':
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/start_job', methods=['POST'])
@login_required
def start_job():
    selected_users = request.form.getlist('selected_users')
    batch_size = int(request.form.get('batch_size', 5))
    
    if not selected_users:
        return jsonify({'status': 'error', 'message': 'No users selected'})
    
    # Create a unique job ID
    job_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Filter credentials for selected users
    credentials_to_run = [cred for cred in all_credentials if cred['phone'] in selected_users]
    
    if not credentials_to_run:
        return jsonify({'status': 'error', 'message': 'No valid credentials found'})
    
    # Create a stop flag for this job
    stop_flag = {'stop': False}
    running_jobs[job_id] = {
        'started_at': datetime.datetime.now(),
        'credentials': credentials_to_run,
        'status': 'running',
        'stop_flag': stop_flag
    }
    
    # Function to check if we should stop
    def should_stop():
        return stop_flag['stop']
    
    # Start worker threads in batches
    def run_batch():
        i = 0
        while i < len(credentials_to_run):
            batch = credentials_to_run[i:i+batch_size]
            threads = []
            
            for cred in batch:
                # Skip if we should stop
                if should_stop():
                    break
                    
                t = threading.Thread(
                    target=run_for_user, 
                    args=(cred, job_id, should_stop)
                )
                t.start()
                threads.append(t)
            
            # Wait for all threads in this batch to complete
            for t in threads:
                t.join()
                
            # Stop if requested
            if should_stop():
                break
                
            i += batch_size
            
        # Update job status when complete
        running_jobs[job_id]['status'] = 'stopped' if should_stop() else 'completed'
        running_jobs[job_id]['completed_at'] = datetime.datetime.now()
    
    # Start the batch processing in a separate thread
    threading.Thread(target=run_batch).start()
    
    return jsonify({
        'status': 'success', 
        'message': f'Job started with ID {job_id}',
        'job_id': job_id
    })

@app.route('/stop_job/<job_id>')
@login_required
def stop_job(job_id):
    if job_id in running_jobs:
        running_jobs[job_id]['stop_flag']['stop'] = True
        running_jobs[job_id]['status'] = 'stopping'
        return jsonify({'status': 'success', 'message': f'Job {job_id} is being stopped'})
    return jsonify({'status': 'error', 'message': 'Job not found'})

@app.route('/job_logs/<job_id>')
@login_required
def get_job_logs(job_id):
    logs = job_logs.get(job_id, [])
    return jsonify({'logs': logs})

@app.route('/job_status')
@login_required
def job_status():
    return jsonify(running_jobs)

@app.route('/manage_credentials', methods=['GET', 'POST'])
@login_required
def manage_credentials():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            phone = request.form.get('phone')
            code = request.form.get('code')
            
            if phone and code:
                all_credentials.append({'phone': phone, 'code': code})
                save_credentials(all_credentials)
        
        elif action == 'delete':
            phone = request.form.get('phone')
            all_credentials[:] = [c for c in all_credentials if c['phone'] != phone]
            save_credentials(all_credentials)
        
        elif action == 'upload':
            if 'file' in request.files:
                file = request.files['file']
                if file:
                    try:
                        uploaded_data = json.loads(file.read())
                        if isinstance(uploaded_data, list):
                            all_credentials.extend(uploaded_data)
                            save_credentials(all_credentials)
                    except Exception as e:
                        return render_template('manage_credentials.html', 
                                              credentials=all_credentials, 
                                              error=f"Upload error: {str(e)}")
    
    return render_template('manage_credentials.html', credentials=all_credentials)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    global CATEGORY_ID, MAX_PAGES, DELAY_SECONDS, MAX_READS
    
    if request.method == 'POST':
        CATEGORY_ID = request.form.get('category_id', CATEGORY_ID)
        MAX_PAGES = int(request.form.get('max_pages', MAX_PAGES))
        DELAY_SECONDS = int(request.form.get('delay_seconds', DELAY_SECONDS))
        MAX_READS = int(request.form.get('max_reads', MAX_READS))
        
        # Save settings to file
        settings = {
            'CATEGORY_ID': CATEGORY_ID,
            'MAX_PAGES': MAX_PAGES,
            'DELAY_SECONDS': DELAY_SECONDS,
            'MAX_READS': MAX_READS
        }
        
        with open('settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
            
    return render_template('settings.html', 
                          category_id=CATEGORY_ID,
                          max_pages=MAX_PAGES,
                          delay_seconds=DELAY_SECONDS,
                          max_reads=MAX_READS)

# Load settings if file exists
def load_settings():
    global CATEGORY_ID, MAX_PAGES, DELAY_SECONDS, MAX_READS
    
    try:
        if os.path.exists('settings.json'):
            with open('settings.json', 'r') as f:
                settings = json.load(f)
                CATEGORY_ID = settings.get('CATEGORY_ID', CATEGORY_ID)
                MAX_PAGES = settings.get('MAX_PAGES', MAX_PAGES)
                DELAY_SECONDS = settings.get('DELAY_SECONDS', DELAY_SECONDS)
                MAX_READS = settings.get('MAX_READS', MAX_READS)
    except Exception as e:
        print(f"Error loading settings: {e}")

# Initialize settings
load_settings()

if __name__ == "__main__":
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
        
    app.run(debug=True, host='0.0.0.0', port=5000)