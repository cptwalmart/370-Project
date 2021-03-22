# Run this script as root

import time
import os
from datetime import datetime as dt
from http.server import SimpleHTTPRequestHandler, HTTPServer
import csv
import threading
import time
import http.server
import socketserver
try:
    import thread
except:
    import _thread as thread
exitFlag = 0

os.system('ipconfig/flushdns')
os.system('nbtstat -R')
print("[ INFO ] PID = ",os.getpid())
def webFilter():
    # change hosts path according to your OS
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    # localhost's IP
    redirect = "127.0.0.1"

    lines_in_header= 9

    website_list = []
    try:
        print("in web filter")
        if False: #comment out reading in websites
            with open('csv.txt', newline='') as csvfile:
                count =0
                #read in lines from file

                lines = csvfile.readlines()
                sites = [line.strip() for line in lines]
                print("in web filter")
                # remove header lines from array
                sites = sites[lines_in_header:]
                for site in sites:


                    # Data process site to be an array of arrays of site info
                    site = site.replace('"', '')
                    site=site.split(",")

                    #Format for site = [id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter]
                    #example site =
                    #['1068863', '2021-03-15 14:22:05', 'http://59.99.143.111:33869/bin.sh',
                    #'offline', 'malware_download', '32-bit', 'elf', 'mips', 'https://urlhaus.abuse.ch/url/1068863/', 'geenensp']

                    if site[3] == "online":
                        website_list.append(site[2])
    except:
        print("[ ERROR ] Could not read in blocked websites. ")
        exit(-1)

    # websites that we can visit to test
    test_list = ["www.facebook.com","facebook.com",
          "dub119.mail.live.com","www.dub119.mail.live.com",
          "www.gmail.com","gmail.com"]

    print("Sites to test this with: ")
    for site in test_list:
        print(site)
        website_list.append(site)


    try:
        with open(hosts_path, 'r+') as file:
            content = file.read()
            for website in website_list:
                if website in content:
                    pass
                else:
                    if(website in test_list):
                        print("site not in content already: "+website)
                    # mapping hostnames to your localhost IP address
                    file.write(redirect + " " + website + "\n")

    except KeyboardInterrupt:
        print("\n[ INFO ] Ending program please wait... ")
        with open(hosts_path, 'r+') as file:
                content=file.readlines()
                file.seek(0)
                for line in content:
                    if not any(website in line for website in website_list):
                        file.write(line)

                # removing hostnames from host file
                file.truncate()
        print("\n[ INFO ] Program ended by Ctrl-C. ")
        os._exit(1)


    #Start hosting local page
    HOST, PORT = "127.0.0.1", 80
    Handler = http.server.SimpleHTTPRequestHandler
    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        try:
            # Activate the server; this will keep running until you
            # interrupt the program with Ctrl-C
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[ INFO ] Ending program please wait... ")
            with open(hosts_path, 'r+') as file:
                    content=file.readlines()
                    file.seek(0)
                    for line in content:
                        if not any(website in line for website in website_list):
                            file.write(line)

                    # removing hostnames from host file
                    file.truncate()
            print("\n[ INFO ] Program ended by Ctrl-C. ")
            server.server_close()
            exit(0)



webFilter()
print("[ INFO exited web filter")
