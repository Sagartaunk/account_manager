import requests
import json
import getpass
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# GENERIC FUNCTIONS
def generic1(url):
    print("Please Enter The Credentials")
    email = input("[~] Username: ")
    password = getpass.getpass("[~] Password: ")
    data = {"email": email, "password": password}
    response = requests.post(url, json=data)
    status = error_handelling(response.status_code)
    if status:
        # Safely try to parse JSON
        try:
            json_data = response.json()
        except requests.exceptions.JSONDecodeError:
            # If not JSON, use text content instead
            json_data = {"message": response.text}
        return [email, password, status, json_data]
    else:
        return generic1(url)

def error_handelling(status):
    match status:
        case 200:
            return True
        case _:
            print("[~] ATTEMPT FAILED!!")
            choice = input("[~] Try Again [y,n] : ")
            if choice == 'y':
                return False
            elif choice == 'n':
                return True
            else:
                print("Invalid Choice")
                return error_handelling(status)

# COMMUNICATION FUNCTIONS

def login(base_url):
    url = f"{base_url}/login"
    response = generic1(url)
    if response[2]:
        print("[~] Successful")
        return response
    else:
        print("[~] Failed to Login")

def register(base_url):
    url = f"{base_url}/register"
    response = generic1(url)
    if response[2]:
        print("[~] Account Created Successfully. Please Login using the details.")
    else:
        print("[~] Failed to Create Account")

def get_data(base_url, email, password):
    url = f"{base_url}/get_data"
    data = {"email": email, "password": password}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        print("[~] Successful")
        
        # Convert response to DataFrame for better display
        result_data = response.json()
        entries = []
        
        for line in result_data.strip().split('\n'):
            if line:
                username = line.split('Username: ')[1].split(',')[0] if 'Username:' in line else "Unknown"
                website = line.split('Website: ')[1] if 'Website:' in line else "Unknown"
                entries.append({"Username": username, "Website": website})
        
        if entries:
            df = pd.DataFrame(entries)
            print("\n[~] Your Stored Accounts:")
            print(df)
        else:
            print("[~] No entries found")
            
        return result_data
    else:
        print("[~] Failed")

def add_data(base_url, email, password):
    url = f"{base_url}/add_data"
    username = input("[~] Email / Username : ")
    website = input("[~] Website : ")
    passwd = getpass.getpass("[~] Password : ")
    data = {
        "email": email,
        "password": password,
        "data": f"{username}:{website}:{passwd}"
    }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        print("[~] Success")
    else:
        print("[~] Failed")

def decrypt(base_url, email, password):
    url = f"{base_url}/get_password"
    username = input("[~] Username to decrypt: ")
    website = input("[~] Website: ")
    data = {
        "email": email,
        "master_password": password,
        "username": username,
        "website": website
    }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        print("[~] Decrypted Data:")
        data = response.json()
        df = pd.DataFrame([data])
        print(df)
    else:
        print("[~] Failed to decrypt or not found.")

def search_entries(base_url, email, password):
    url = f"{base_url}/get_data"
    data = {"email": email, "password": password}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        entries = response.json()
        query = input("[~] Search for (username/website): ").lower()
        print("[~] Search Results:")
        results = []
        for entry in entries.strip().split('\n'):
            if query in entry.lower():
                print(entry)
                username = entry.split('Username: ')[1].split(',')[0] if 'Username:' in entry else "Unknown"
                website = entry.split('Website: ')[1] if 'Website:' in entry else "Unknown"
                results.append({"Username": username, "Website": website})
        
        if results:
            df = pd.DataFrame(results)
            print("\n[~] Matched Entries:")
            print(df)
        else:
            print("[~] No matching entries found")
    else:
        print("[~] Failed to fetch entries.")

# ADMIN FUNCTIONS
def admin_login(base_url):
    print("[~] Admin Login Required")
    email = input("[~] Admin Username: ")
    password = getpass.getpass("[~] Admin Password: ")
    return email, password

def admin_get_dates(base_url):
    email, password = admin_login(base_url)
    auth_token = f"{email}:{password}"
    url = f"{base_url}/api/admin_get_dates"
    response = requests.post(url, 
                           json=email,
                           headers={"Authorization": f"Bearer {auth_token}"})
    
    if response.status_code == 200:
        print("[~] Successful")
        data = response.json()
        
        # Convert to DataFrame for better display
        dates_list = []
        for date_str in data.split(","):
            if date_str.strip():
                dates_list.append(date_str.strip())
        
        date_counts = Counter(dates_list)
        df = pd.DataFrame.from_dict(date_counts, orient='index', columns=['Count'])
        df.index.name = 'Date'
        print("\n[~] Account Creation Dates:")
        print(df)
        
        # Plot pie chart
        plt.figure(figsize=(10, 6))
        plt.pie(date_counts.values(), labels=date_counts.keys(), autopct='%1.1f%%')
        plt.title('Account Creation Dates Distribution')
        plt.axis('equal')  # Equal aspect ratio ensures pie is drawn as a circle
        plt.show()
        
        return data
    else:
        print(f"[~] Failed with status code: {response.status_code}")
        return None

def admin_create_account(base_url):
    email, password = admin_login(base_url)
    auth_token = f"{email}:{password}"
    
    print("[~] Create New Admin Account")
    new_admin = input("[~] New Admin Username: ")
    new_password = getpass.getpass("[~] New Admin Password: ")
    
    data = {"email": new_admin, "password": new_password}
    url = f"{base_url}/api/admin_create"
    response = requests.post(url, 
                           json=data,
                           headers={"Authorization": f"Bearer {auth_token}"})
    
    if response.status_code == 200:
        print("[~] Admin Account Created Successfully")
        print(response.json())
    else:
        print(f"[~] Failed with status code: {response.status_code}")

def admin_mode(base_url):
    print("\n[~] ADMIN MODE")
    print("Type 'Help' for available commands or 'EXIT' to return to main menu")
    
    while True:
        admin_cmd = input("[ADMIN] ")
        match admin_cmd:
            case "Dates":
                admin_get_dates(base_url)
            case "CreateAdmin":
                admin_create_account(base_url)
            case "Help":
                print("Dates : View account creation dates (with visualization)")
                print("CreateAdmin : Create a new admin account")
                print("EXIT : Return to main menu")
            case "EXIT":
                print("[~] Exiting admin mode")
                return
            case _:
                print("[~] Unknown admin command. Type 'Help' for available commands.")


# MAIN FUNCTION
print("Welcome to Password Manager")
print("Type 'Help' for help")
email = ""
password = ""
base_url = "http://192.168.0.100:51020"  # Change to your middleware server

while True:
    match input("[~] "):
        case "Login":
            result = login(base_url)
            if result:
                email = result[0]
                password = result[1]
        case "Register":
            register(base_url)
        case "Get":
            if email and password:
                get_data(base_url, email, password)
            else:
                print("[~] Please login first.")
        case "Add":
            if email and password:
                add_data(base_url, email, password)
            else:
                print("[~] Please login first.")
        case "Decrypt":
            if email and password:
                decrypt(base_url, email, password)
            else:
                print("[~] Please login first.")
        case "Search":
            if email and password:
                search_entries(base_url, email, password)
            else:
                print("[~] Please login first.")
        case "ADMIN":
            admin_mode(base_url)
        case "Help":
            print("Here is a list of all commands you can perform : ")
            print("Login : To login into an account")
            print("Register : To register a new account")
            print("Get : To get the usernames and websites associated with the account")
            print("Add : To add a new username/website/password")
            print("Decrypt : To decrypt the password for a username/website")
            print("Search : To search your entries")
            print("ADMIN : Enter admin mode (requires admin credentials)")
            print("Exit : To Exit the program")
        case "Exit":
            break
        case _:
            print("[~] Unknown command. Type 'Help' for help.")