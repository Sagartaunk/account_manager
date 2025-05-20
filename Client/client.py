import requests
import json
import getpass

# GENERIC FUNCTIONS
def generic1(url):
    print("Please Enter The Credentials")
    email = input("[~] Username: ")
    password = getpass.getpass("[~] Password: ")
    data = {"email": email, "password": password}
    response = requests.post(url, json=data)
    status = error_handelling(response.status_code)
    if status:
        return [email, password, status, response.json()]
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
        print(response.json())
        return response.json()
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
        print(response.json())
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
        for entry in entries.split(","):
            if query in entry.lower():
                print(entry)
    else:
        print("[~] Failed to fetch entries.")

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
        case "Help":
            print("Here is a list of all commands you can perform : ")
            print("Login : To login into an account")
            print("Register : To register a new account")
            print("Get : To get the usernames and websites associated with the account")
            print("Add : To add a new username/website/password")
            print("Decrypt : To decrypt the password for a username/website")
            print("Search : To search your entries")
            print("Exit : To Exit the program")
        case "Exit":
            break
        case _:
            print("[~] Unknown command. Type 'Help' for help.")