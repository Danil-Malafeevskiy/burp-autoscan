import sys

def start(dict_for_input_data):

    api_socket = input("Enter the socket for the REST API (default: 127.0.0.1:1337): ") or "127.0.0.1:1337"
    api_key = input("Enter the API key for the REST API (default: HjvVhzWBFGZdLRQXkhNTvQAUK4u94aKR): ") or "HjvVhzWBFGZdLRQXkhNTvQAUK4u94aKR"

    with open(sys.argv[1]) as file:
        dict_for_input_data['urls'] = [row.strip() for row in file]

    names_scan_config = (input("Enter the name of the scan configuration from the library (default: Crawl and Audit - Lightweight): ") or "Crawl and Audit - Lightweight").split(',')
    scan_config = []
    for name in names_scan_config:
        scan_config.append({"name": name, "type": "NamedConfiguration"})
    dict_for_input_data['scan_configurations'] = scan_config

    protocol_options = input("Enter protocol configuration (default: httpAndHttps):") or "httpAndHttps"
    dict_for_input_data["protocol_option"] = protocol_options

    application_login = input("Will authorized scanning be used? (Y/n)") or "n"
    login_data = []
    while application_login == "Y":
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        login_data.append({'password': password, "username": username, "type": "UsernameAndPasswordLogin"})

        application_login = input("Will there be more login details? (Y/n)") or "n"
    if login_data:
        dict_for_input_data["application_logins"] = login_data

    return api_socket, api_key