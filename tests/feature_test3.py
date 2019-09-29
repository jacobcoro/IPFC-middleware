import requests
# For API get- importing from IPFS
url = "https://ipfcmidware.azurewebsites.net/"
headers = {"email": "123"}
r = requests.get(url, headers=headers)
pastebin_text = r.text
data = r.json
print("The pastebin text is:%s" % pastebin_text)
print(data)
