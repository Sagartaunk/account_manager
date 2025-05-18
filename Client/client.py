import requests
import json
import getpass

#GENERIC FUNCTIONS
def generic1(url) : #Sends The Server Email And Password
    print("Please Enter The Credentials")
    email = input("[~] Username: ")
    password = getpass.getpass("[~] Password: ")
    data = {"email":email , "password":password}
    response = requests.post(url ,json=data)
    status = error_handelling(response.status_code)
    if status :
        return [email , password , status , response.json]
    else :
        generic1(url)
    

     
def error_handelling(status) : #Handels The Errors
    match status :
        case 200 :
            return True 
        case _ :
            print("[~] ATTEMPT FAILED!!")
            choice = input("[~] Try Again [y,n] : ")
            if choice == 'y' :
                return False
            elif choice == 'n' :
                return True
            else :
                print("Invalid Choice")
                error_handelling(status)



#COMMUNICATION FUNCTIONS

def login(base_url): #Contacts Login endpoint
    url = f"{base_url}/login"
    response = generic1(url)
    if response[2] :
        print("Successfull")
        return response
    else :
        print("Failed to Login")


def register(base_url): #Contacts Register endpoint
    url = f"{base_url}/register"
    response = generic1(url)
    if response[2] :
        print("[~] Account Created Successfully Please Login using the details ")
    else :
        print("[~] Failed to Create Account ")

def get_data(url , data) : #Used to fetch usernames and websites of the stored accounts
    url = f"{url}/get_data"
    response = generic1(url , json=data)
    if response[2] :
        print("[~] Successful")
        print(response[3])
        return response[3]
    else :
        print("[~] Failed ")

def add_data(url , data) : #Used to add data to the master account 
    url = f"{url}/add_data"
    email = input("[~] Email / Username : ")
    website = input("[~] Website : ")
    password = getpass.getpass("[~] Password : ")
    data.append({"data" : f"{email}:{website}:{password}"})
    response = requests.post(url ,json=data)
    if response.status_code == 200 :
        print("[~] Success")
    else :
        print("[~] Failed")

def decrypt(url , data) :
    data = get_data(url , data)



#MAIN FUNCTION
print("Welcome to Password Manager")
print("Type 'Help' for help")
email = ""
password = ""
base_url = "http://192.168.0.100:51020" #write the url of the middleware server 
while True :
    match input("[~] ") :
        case "Login" :
            result = login(base_url)
            email = result[0]
            password = result[1]

        case "Register" :
            result = register(base_url)
        
        case "Get" :
            get_data(base_url , {"email" : email , "password" : password})
        
        case "Add" :
            add_data(base_url , {"email" : email , "password" : password})
        case "Decrypt" :
            decrypt(base_url , {"email" : email , "password" : password})
        case "Admin" :
            print("Under Construction")
        case "Help" :
            print("Here is a list of all commands you can perform : ")
            print("Login : To login into a account \nRegister : To rgister a new account \nGet : To get the usernames and websites associated with the account \nDecrypt : Shows the list of associated usernames and websites and allows to decrypt the password of one account \nAdmin : To enter admin page \nExit : To Exit the program")
        case "Exit" :
            break
        case "Admin" :
            print("Under Construction")