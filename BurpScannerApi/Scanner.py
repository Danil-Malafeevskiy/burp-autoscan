import json
import logging
from time import sleep
import re
from PyBurprestapi.burpscanner import BurpApi


class Scanner(object):

    def __init__(self, api_socket, api_key, data):

        self.burp_api = BurpApi(f'http://{api_socket}/', api_key)
        self.data = data

    def process_scan(self):
        logging.getLogger().setLevel(logging.INFO)
        logging.info(f'Start scanner!')

        burp_scan = self.burp_api.scan(data=json.dumps(self.data))

        if burp_scan.response_headers == None:
            logging.error(burp_scan)
            return

        task_id = burp_scan.response_headers["Location"]
        status = self.burp_api.scan_info(task_id).data['scan_status']

        logging.info(f'Scan_status: {status}')
        while status != "succeeded" and status != "failed":
            new_info = self.burp_api.scan_info(task_id).data
            new_status = new_info['scan_status']
            if (new_status == "paused" and new_info['scan_metrics']['crawl_and_audit_caption'].startswith('Paused task due to:')):
                if (not new_info['scan_metrics']['crawl_and_audit_caption'].endswith('Reached time limit for task')):
                    logging.error(new_info['scan_metrics']['crawl_and_audit_caption'])
                    return
                else:
                    logging.info(new_info['scan_metrics']['crawl_and_audit_caption'])
                    break

            if new_status != status: 
                logging.info(f'Scan_status: {new_status}')
                status = new_status
            
            sleep(2)

        self.report_scan(task_id)

    def report_scan(self, task_id: int):
        count_issue = 1
        
        with open(f'results/{task_id}.txt', "a") as file:
            scan_res = self.burp_api.scan_info(task_id).data

            if scan_res == None:
                file.write("No vulnerabilities found!")
                print("No vulnerabilities found!")
                return
            
            for i in scan_res['issue_events']:
                file.write(f"{count_issue}) name: {i['issue']['name']}\norigin: {i['issue']['origin']}\nissue_background: {re.sub('<[^>]+>', ' ', i['issue']['issue_background'])}\nindex_issue: {i['issue']['type_index']}\n")
                try:
                    file.write(f"description: {re.sub('<[^>]+>', ' ', i['issue']['description'])}\n\n")
                except KeyError:
                    file.write("descrition: Описания нет.\n\n")
                count_issue+=1

        print(f"Your data is written to a file: {task_id}.txt")