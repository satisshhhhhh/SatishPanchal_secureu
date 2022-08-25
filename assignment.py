import requests
import socket
import ssl
import sys

# variables where we'll store our data in...
valid_subdomains = []
ssl_certificate = ""
ports_scanned = []
xss = ""

#fetching subdomains of given website
def fetch_subdomains(dom_name, sub_dom):
    count = 0
    print('[+] Subdomains:')
    
    for subdomain in sub_dom:
        # in order to check whehter the irl exists or not
        # we need to pu subdomain one by one
        url = f'https://{subdomain}.{dom_name}'
        
        try:
            # sending get request to the url
            res = requests.get(url)
            
            # printing the subdomain if the url exists
            print(f'[{res.status_code}] - {subdomain}.{dom_name}')
            # appending subdomains to our list
            valid_subdomains.append(f"[{res.status_code}] - {subdomain}.{dom_name}")
            # incrementing our url
            count = count + 1
            
        except requests.ConnectionError:
            # if subdomain doe not exists just pass
            pass
    print("\n[+] Total Subdomains Found :",count)
    

def check_SSL(domain):
    print("[+] SSL Details :")
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        try:        
            s.connect((hostname, 443))
            print("- SSL : Enabled")
            ssl_certificate = "Enabled"
        except:
            print("- SSL : Disabled")
            ssl_certificate = "Disabled"

    print(f'- issued_to : {domain}')


def scan_ports():
    print("[+] Ports")
    target = socket.gethostbyname(socket.gethostname())

    try:
        for port in range(1,250):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.01)

            # returns an error indicator
            result = s.connect_ex((target,port))
            if result ==0:
                print(f"Port {port}\t : Open")
                ports_scanned.append(f"Port {port}\t : Open")
            s.close()

    except KeyboardInterrupt:
            print("\n Exiting Program !!!!")
            sys.exit()
    except socket.gaierror:
            print("\n Hostname Could Not Be Resolved !!!!")
            sys.exit()
    except socket.error:
            print("\ Server not responding !!!!")
            sys.exit()

            
def x_xss_protection(domain):
    print("[+] Header :")
    url="https://"+domain
    res=requests.get(url)
    if res.headers['x-xss-protection']=='1':
        xss = ("X-XSS-Protection : Enabled")
    else:
        xss = ("X-XSS-Protection : Disabled")
    print(xss)

    
# Driver code or Main Function
if __name__ == '__main__':
    
    dom_name = input("Enter the Domain Name : ")
    print("\n")
  
    # opening the text file that contains all out subdomain names
    with open('D:\\My Projects\\Secure-U\\names.txt','r') as file:

        name = file.read()
          
        # storing the list of splitted strings
        sub_dom_names = name.splitlines()
          
    print(f'[+] URL: {dom_name}')
    print("-" * 40)
    
    fetch_subdomains(dom_name,sub_dom_names)
    print("-" * 40)
    
    check_SSL(dom_name)
    print("-" * 40)
    
    scan_ports()
    print("-" * 40)
    
    x_xss_protection(dom_name)
    
    # File Handling
    
    # Finally we'll add our outputs into one log.txt file
    try:
        logs_file = open("logs.txt", 'w')
        logs_file.write(f'[+] URL: {dom_name}\n')
        logs_file.write("----------------------------------------\n")
        logs_file.write("[+] SSL Details :\n")
        for sub in valid_subdomains:
            logs_file.write(f"- {sub}\n")
        logs_file.write(f"[+] Total Subdomains are : {len(valid_subdomains)}\n")
        logs_file.write("----------------------------------------\n")
        logs_file.write("[+] SSL Details : ")
        logs_file.write(f"- SSL: {ssl_certificate} \n - issued_to : {dom_name}\n")
        logs_file.write("----------------------------------------\n")
        logs_file.write("[+] Ports\n")
        for port in ports_scanned:
            logs_file.write(f"{port}\n")
        logs_file.write("----------------------------------------\n")
        logs_file.write("[+] Header : \n {xss}")
        print("\n Checkout logs.txt!")
    except:
        print("Something went wring while creating logs.txt :(")