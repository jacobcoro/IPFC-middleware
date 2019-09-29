import requests
import argon2
import json
import uuid
import secrets

api_url = "https://ipfcmidware.azurewebsites.net/"
entered_email = "12@12.12"
# entered_email = self.ui.lineEditEmail.text()
entered_password = "Password123"
# entered_password = self.ui.lineEditPassword.text()
user_id = ""

def get_salt(email):
    url = api_url + "getsalt"
    form_data = {"email": email}
    req = requests.get(url, data=form_data)
    api_response = json.loads(req.text)
    return api_response

def get_userid():
    url = api_url + "getuserid"
    email = "123@123.com"
    form_data = {"email": email}
    req = requests.get(url, data=form_data)
    api_response = json.loads(req.text)
    global user_id
    user_id = api_response

def verify_login(email, password):
    stored_salt = get_salt(email)
    trial_key = argon2.argon2_hash(password=password, salt=stored_salt, t=16, m=512, p=2, buflen=64).hex()
    url = api_url + "verifylogin"
    form_data = {"email": email, "key": str(trial_key)}
    req = requests.get(url, data=form_data)
    api_response = json.loads(req.text)
    if not api_response:
        # self.ui.labelResponse.setText('Incorrect login information.')
        print('incorrect login!')
        return False
    if api_response:
        # self.open_start_menu()
        get_userid()
        print("correct login!")
        return True


def verify_signup():
    new_email = self.ui.lineEditEmail.text()
    password = self.ui.lineEditPassword.text()
    repeat_password = self.ui.lineEditPassword.text()
    pinata_api = self.ui.lineEditPinataAPI.text()
    pinata_key = self.ui.lineEditPinataKey.text()
    new_user_id = uuid.uuid4().hex
    new_salt = secrets.token_hex(32)
    key = argon2.argon2_hash(password=password, salt=new_salt, t=16, m=512, p=2, buflen=64).hex()
    if new_email == "" or password == "" or repeat_password == "" or pinata_api == "" or pinata_key == "":
        #self.ui.labelResponse.setText("All fields are required")
        return
    elif "@" not in new_email and "." not in new_email:
        #self.ui.labelResponse.setText("Please input a valid email address")
        return
    elif len(password) < 8:
        #self.ui.labelResponse.setText("Password must be more than 8 characters long")
        return
    elif password != repeat_password:
        #self.ui.labelResponse.setText("Passwords did not match")
        return
    else:
        url = api_url + 'verifysignup'
        form_data = {"email": new_email, "new_user_id": new_user_id, "new_email": new_email, "key": key,
                     "new_salt": new_salt, "pinata_api": pinata_api, "pinata_key": pinata_key}
        req = requests.get(url, data=form_data)
        api_response = json.loads(req.text)
        if api_response == "email_exists":
            print("email exists")
            #self.ui.labelResponse.setText("Email already already in database.")
            return
        if api_response == "success":
            print("success")
            #self.ui.labelResponse.setText("Sign up successful!")
            # add something here to query database and see if values are all there properly?
            return
        else:
            #self.ui.labelResponse.setText("error")
            print("error")
            return


verify_signup()