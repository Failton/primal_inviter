from modules.anticaptchacom import abuzHCaptchaProxyless
from user_agent import generate_user_agent
from modules.mobileproxy import mobileProxy
from time import time, sleep
from loguru import logger
from sys import stderr
from art import tprint
from dotenv import dotenv_values
import concurrent.futures
import random
import requests
import poplib
import quopri
import string

# SETTINGS
ENV = dotenv_values('.env')
PROXY = ENV['MOBILE_PROXY']
CHANGE_IP_LINK = ENV['MOBILE_CHANGE_IP_LINK']
POP3_SERVER = ENV['POP3_SERVER']
REFERRAL_CODE = ENV['REFERRAL_CODE']
ANTICAPTCHA_KEY = ENV['ANTICAPTCHA_KEY']

file_mails = 'files/mails.txt'
file_registered = 'files/registered.txt'
file_blacklist = 'files/blacklist.txt'
file_log = 'files/log.log'

website_url = 'https://byrjycocvluocdgliyvg.supabase.co'
site_key = 'c4344dc0-0182-431f-903c-d8f53065d81d'

# LOGGING SETTING
logger.remove()
logger.add(stderr, format="<white>{time:HH:mm:ss}</white> | <level>{level: <8}</level> | <cyan>{line}</cyan> - <white>{message}</white>")
logger.add(file_log, format="<white>{time:HH:mm:ss}</white> | <level>{level: <8}</level> | <cyan>{line}</cyan> - <white>{message}</white>")

def get_mail_numbers_before(email_address, password):
    pop3server = poplib.POP3_SSL(POP3_SERVER)
    pop3server.user(email_address)
    pop3server.pass_(password)
    pop3info = pop3server.stat()
    mailcount = pop3info[0]
    return (mailcount)

def get_activate_link(email_address, password, mail_numbers_before):
    while True:
        pop3server = poplib.POP3_SSL(POP3_SERVER)
        pop3server.user(email_address)
        pop3server.pass_(password)
        pop3info = pop3server.stat()
        mailcount = pop3info[0]
        if (mailcount != mail_numbers_before):
            break
    message = ''
    for i in pop3server.retr(mailcount)[1]:
        message += quopri.decodestring(i).decode('latin-1')
    code = message[-96:-90]
    pop3server.quit()
    return(code)

def setup_session(mail):
    session = requests.Session()
    headers = {
            'Host': 'byrjycocvluocdgliyvg.supabase.co',
            'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ5cmp5Y29jdmx1b2NkZ2xpeXZnIiwicm9sZSI6ImFub24iLCJpYXQiOjE2Njc0MDY3NzksImV4cCI6MTk4Mjk4Mjc3OX0.SLAgTxtgawJoxTXXtxfI85Q3Xz-ecBI9XkjZyKvl794',
            'apikey': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ5cmp5Y29jdmx1b2NkZ2xpeXZnIiwicm9sZSI6ImFub24iLCJpYXQiOjE2Njc0MDY3NzksImV4cCI6MTk4Mjk4Mjc3OX0.SLAgTxtgawJoxTXXtxfI85Q3Xz-ecBI9XkjZyKvl794',
            'x-client-info': 'supabase-js/2.0.5',
            'content-type': 'application/json;charset=UTF-8',
            'accept-encoding': 'gzip',
            'user-agent': 'okhttp/4.9.2',
            }
    session.headers = headers
    session.proxies.update({'https': 'http://' + PROXY})
    return session

def register(mail, password):
    try:
        try:
            mail_numbers_before = get_mail_numbers_before(mail, password)
        except:
            with open(file_blacklist, 'a') as file:
                file.write(f'{mail}:{password}\n')
            logger.error(f"{mail}:{password} POP3 not activated")
            return 1

        session = setup_session(mail)

        captcha = abuzHCaptchaProxyless(ANTICAPTCHA_KEY, website_url, site_key, verbose=False)
        logger.info(f"Solving captcha: {mail}")
        while True:
            captcha_token, captcha_error = captcha.get_token_solution()
            if (captcha_error == 1):
                logger.error(f'Captcha error, solving again: {mail} | Code error: {captcha_token}')
            else:
                logger.success(f'Captcha solved: {mail}')
                break

        payload_otp = {
                "email": mail,
                "data": {},
                "create_user": True,
                "gotrue_meta_security": {
                    'captcha_token': captcha_token,
                    },
                }
        try:
            resp_otp = session.post('https://byrjycocvluocdgliyvg.supabase.co/auth/v1/otp', json=payload_otp)
            if (resp_otp.status_code == 200):
                logger.success(f"Success OTP: {mail}, {resp_otp.text}")
            else:
                logger.error(f"Error OTP: {mail} | Status code: {resp_otp.status_code} | Response text: {resp_otp.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        #------------------------------------------------------------------------------------------------------
        while True:
            try:
                token = get_activate_link(mail, password, mail_numbers_before)
                break
            except:
                pass
        logger.info(f"Code from mail: {token}")
        payload_verify = {
                "email": mail,
                "token": token,
                "type": "magiclink",
                "gotrue_meta_security": {}
                }
        try:
            resp_verify = session.post('https://byrjycocvluocdgliyvg.supabase.co/auth/v1/verify', json=payload_verify)
            if (resp_verify.status_code == 200):
                logger.success(f"Success mail verify: {mail}, {resp_verify.text}")
            else:
                logger.success(f"Mail verify (its ok!): {mail} | Status code: {resp_verify.status_code} | Response text: {resp_verify.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        if ('access_token' in resp_verify.json()):
            bearer_token = resp_verify.json()['access_token']
            session.headers.update({'authorization': 'Bearer ' + bearer_token})
        else:
            payload_verify = {
                    "email": mail,
                    "token": token,
                    "type": "signup",
                    "gotrue_meta_security": {}
                    }
            try:
                resp_verify = session.post('https://byrjycocvluocdgliyvg.supabase.co/auth/v1/verify', json=payload_verify)
                if (resp_verify.status_code == 200):
                    logger.success(f"Success mail verify: {mail}, {resp_verify.text}")
                else:
                    logger.error(f"Error mail verify: {mail} | Status code: {resp_verify.status_code} | Response text: {resp_verify.text}")
            except Exception as error:
                logger.error(f"Unexcepted error: {error}")
                return 1

            bearer_token = resp_verify.json()['access_token']
            session.headers.update({'authorization': 'Bearer ' + bearer_token})
            
        #------------------------------------------------------------------------------------------------------

        payload_ref = {
                "code": REFERRAL_CODE,
                }
        try:
            resp_referral_code_valid = session.post('https://byrjycocvluocdgliyvg.supabase.co/rest/v1/rpc/referral_code_valid', json=payload_ref)
            if (resp_referral_code_valid.status_code == 200):
                logger.success(f"Success referral code valid check: {mail}, {resp_referral_code_valid.text}")
            else:
                logger.error(f"Error referral code valid check: {mail} | Status code: {resp_referral_code_valid.status_code} | Response text: {resp_referral_code_valid.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        #------------------------------------------------------------------------------------------------------

        payload_ref = {
                "code": REFERRAL_CODE,
                }
        try:
            resp_set_referred_by = session.post('https://byrjycocvluocdgliyvg.supabase.co/rest/v1/rpc/set_referred_by', json=payload_ref)
            if (resp_set_referred_by.status_code == 200):
                logger.success(f"Success set referral: {mail}, {resp_set_referred_by.text}")
            else:
                logger.error(f"Error set referral: {mail} | Status code: {resp_set_referred_by.status_code} | Response text: {resp_set_referred_by.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        #------------------------------------------------------------------------------------------------------

        username = ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 15)))
        logger.info(f'Generated username: {username}')
        payload_username = {
                "username": username,
                }
        try:
            resp_username_valid = session.post('https://byrjycocvluocdgliyvg.supabase.co/rest/v1/rpc/username_valid', json=payload_username)
            if (resp_username_valid.status_code == 200):
                logger.success(f"Success username check: {mail}, {resp_username_valid.text}")
            else:
                logger.error(f"Error username check: {mail} | Status code: {resp_username_valid.status_code} | Response text: {resp_username_valid.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        #------------------------------------------------------------------------------------------------------

        payload_username = {
                "username": username,
                }
        try:
            resp_set_username = session.post('https://byrjycocvluocdgliyvg.supabase.co/rest/v1/rpc/set_username', json=payload_username)
            if (resp_set_username.status_code == 200):
                logger.success(f"Success username set: {mail}, {resp_set_username.text}")
            else:
                logger.error(f"Error username set: {mail} | Status code: {resp_set_username.status_code} | Response text: {resp_set_username.text}")
        except Exception as error:
            logger.error(f"Unexcepted error: {error}")
            return 1

        #------------------------------------------------------------------------------------------------------

        logger.success("DONE!!!!!!!!")
        with open(file_registered, 'a') as file:
            file.write(f'{mail}:{password}:{username}\n')
    except:
        pass


if (__name__ == '__main__'):
    tprint(text="PRIMAL INVITER", font="standart")
    tprint(text="t.me/cryptogovnozavod", font="cybermedum")
    with open(file_mails, 'r') as file:
        all_mails = [row.strip().split(':') for row in file]
    with open(file_registered, 'r') as file:
        registered = [row.strip().split(':')[:2] for row in file]
    with open(file_blacklist, 'r') as file:
        blacklist = [row.strip().split(':')[:2] for row in file]

    mails = [x for x in all_mails if (x not in registered and x not in blacklist)]

    mobile_proxy = mobileProxy(PROXY, CHANGE_IP_LINK)
    
    logger.info("Подпишись t.me/cryptogovnozavod!")
    for mail in mails:
        while True:
            try:
                mobile_proxy.change_ip() 
                logger.info('Successfully changed IP')
                break
            except:
                continue
        sleep(2)
        register(mail[0], mail[1])
