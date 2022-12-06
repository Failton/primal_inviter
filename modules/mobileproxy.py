from time import sleep
import requests

class mobileProxy():
    def __init__(self, proxy, change_ip_link):
        self.proxy = proxy
        self.change_ip_link = change_ip_link

    def change_ip(self):
        resp = requests.get(self.change_ip_link)
        assert resp.status_code == 200, f"Error while changing IP address, request status code: {resp.status_code}"

    def get_ip_address(self):
        proxies = {'https': 'http://' + self.proxy} 
        resp = requests.get('https://api.ipify.org/?format=json', proxies=proxies)
        assert resp.status_code == 200, f"Error while getting IP address, request status code: {resp.status_code}"
        ip_address = resp.json()['ip']
        return ip_address
