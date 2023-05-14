import urllib.request
import hashlib

hash = input('>> Input Sha1 hash Value: ')
url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
passList = urllib.request.urlopen(url)

for _pass in passList:
    _pass = _pass.decode("utf-8")
    _pass = _pass[:len(_pass)-1]
    guess = hashlib.sha1(bytes(_pass, "utf-8")).hexdigest()
    if guess == hash:
        print("[0] --- Password is : " + str(_pass))
        exit(0)
    else:
        pass

print("[-] Password could not be cracked")
