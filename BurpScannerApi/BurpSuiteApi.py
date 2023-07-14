from time import sleep
from input_data import start
from Scanner import Scanner
import threading as tr
import subprocess
import os

BurpSuite = subprocess.Popen("cmd /c BurpSuite.vbs", shell=True)

print("Wait. Burp Suite starts...")
sleep(5)

input_data = {}
api_socket, api_key = start(input_data)

burp_api = Scanner(api_socket, api_key, input_data)

scan_process = tr.Thread(target=burp_api.process_scan, args=(), daemon=True)

scan_process.start()
scan_process.join()

os.system("taskkill /f /im java.exe")