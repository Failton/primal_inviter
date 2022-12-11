from anticaptchaofficial.hcaptchaproxyless import *

class abuzHCaptchaProxyless(hCaptchaProxyless):
    def __init__(self, api_key, website_url, site_key, verbose=False):
        self.set_verbose(verbose)
        self.set_key(api_key)
        self.set_website_url(website_url)
        self.set_website_key(site_key)
        self.set_is_invisible(1)

    def get_token_solution(self):
        hcaptcha_resp = self.solve_and_return_solution()
        if hcaptcha_resp != 0:
            return (hcaptcha_resp, 0)
        else:
            return (self.error_code, 1)
