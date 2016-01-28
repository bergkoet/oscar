#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
import struct
import select
import socket
import random
import hashlib
import hmac
import base64
import io
import requests

import trello
from twilio.rest import TwilioRestClient

import smtplib

from lib import trellodb
from lib import conf


""" Function and class definitions """
def parse_scanner_data(scanner_data):
    upc_chars = []
    for i in range(0, len(scanner_data), 16):
        chunk = scanner_data[i:i+16]

        # The chunks we care about will match
        # __  __  __  __  __  __  __  __  01  00  __  00  00  00  00  00
        if chunk[8:10] != '\x01\x00' or chunk[11:] != '\x00\x00\x00\x00\x00':
            continue

        digit_int = struct.unpack('>h', chunk[9:11])[0]
        upc_chars.append(str((digit_int - 1) % 10))

    return ''.join(upc_chars)


# Potential problems getting descriptions from the UPC database
class CodeInvalid(Exception): pass
class SignatureInvalid(Exception): pass
class RequireFunds(Exception): pass
class CodeNotFound(Exception): pass


class UPCAPI:
    BASEURL = 'https://www.digit-eyes.com/gtin/v2_0'
    SUCCESS = 200  # Return status code for successful retrieval

    def __init__(self, app_key, auth_key):
        self._app_key = app_key
        self._auth_key = auth_key

    def _signature(self, upc):
        h = hmac.new(self._auth_key, upc, hashlib.sha1)
        return base64.b64encode(h.digest())

    def _decode_errors(self, response):
        """ Translate HTTP error status codes for retrieval operation and raise
        appropriate exception.  Codes last updated 01/28/16. """
        code = response.status_code
        message = response.json()['return_message']
        known_errors = {
            400: CodeInvalid,  # UPC/EAN Code invalid
            401: SignatureInvalid,  # Signature invalid
            402: RequireFunds,  # Requires funding
            404: CodeNotFound,  # UPC/EAN not found
        }
        try:
            raise known_errors[code](message)
        except ValueError:  # Unknown error
            response.raise_for_status()


    def get_description(self, upc):
        """Returns the product description for the given UPC.

           `upc`: A string containing the UPC."""
        response = requests.get(self.BASEURL, params=[
            ('upcCode', upc),
            ('field_names', 'description'),
            ('language', 'en'),
            ('app_key', self._app_key),
            ('signature', self._signature(upc))
        ])
        if response.status_code == self.SUCCESS:
            return response.json()['description']
        else:
            self._decode_errors(response)


class FakeAPI:
    def get_description(self, upc):
        raise CodeNotFound("Code {0} was not found.".format(upc))


def local_ip():
    """Returns the IP that the local host uses to talk to the Internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("trello.com", 80))
    addr = s.getsockname()[0]
    s.close()
    return addr


def generate_opp_id():
    return ''.join(random.sample('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 12))


def opp_url(opp):
    return 'http://{0}:{1}/learn-barcode/{2}'.format(
        local_ip(), conf.get()['port'], opp['opp_id'])


def create_barcode_opp(trello_db, barcode, desc=''):
    """Creates a learning opportunity for the given barcode and writes it to Trello.

       Returns the dict."""
    print "Creating learning opportunity for barcode {}.".format(unicode(barcode))
    opp = {
        'type': 'barcode',
        'opp_id': generate_opp_id(),
        'barcode': barcode,
        'desc': desc,
        'created_dt': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    trello_db.insert('learning_opportunities', opp)
    return opp


def publish_unknown(opp):
    """ The barcode wasn't found in the database, so there is no known
    description or suggestions. """
    print "Publishing learning opportunity without description."
    subject = '''Didn't Recognize Barcode'''
    message = '''Hi! Oscar here. You scanned a code ({}) I didn't recognize.  '''.format(opp['barcode'])
    message += '''Care to fill me in?''' + '\n' + opp_url(opp)

    communication_method = conf.get()['communication_method']
    if communication_method == 'email':
        send_via_email(message, subject)
    else:
        send_via_twilio(message)


def publish_learning_opp(opp, suggestions):
    """ The barcode and description were found, but we'll offer to learn a
    nickname for next time. """
    print "Publishing learning opportunity with description."
    subject = '''Learning: {}'''.format(opp['desc'])
    message = '''Hi! Oscar here. I added a new item "{}" to the list.'''.format(opp['desc'])
    message += '''\nYou can create a shorter name to use next time here:'''
    message += '\n'+opp_url(opp)
    if suggestions:
        # Add links to auto-learn a suggested nickname
        message += '''\nor you can quickly select one of the following:'''
        for name in suggestions:
            req = requests.Request('GET', opp_url(opp), params={'item': name}).prepare()
            message += '\n\'{name}\' -> {url}'.format(url=req.url, name=name)

    communication_method = conf.get()['communication_method']
    if communication_method == 'email':
        send_via_email(message, subject)
    else:
        send_via_twilio(message)


def send_via_twilio(msg):
    client = TwilioRestClient(conf.get()['twilio_sid'], conf.get()['twilio_token'])
    message = client.sms.messages.create(body=msg,
                                         to='+{0}'.format(conf.get()['twilio_dest']),
                                         from_='+{0}'.format(conf.get()['twilio_src']))


def send_via_email(msg, subject):
    to = conf.get()['email_dest']
    gmail_user = conf.get()['gmail_user']
    gmail_pwd = conf.get()['gmail_password']
    smtpserver = smtplib.SMTP("smtp.gmail.com",587)
    smtpserver.ehlo()
    smtpserver.starttls()
    smtpserver.ehlo
    smtpserver.login(gmail_user, gmail_pwd)
    header = 'To:' + to + '\n' + 'From: ' + gmail_user + '\n' + 'Subject: ' + subject + ' \n'
    print '\nSending email...\n'
    message = header + '\n ' + msg +' \n\n'
    smtpserver.sendmail(gmail_user, to, message)
    print 'Email sent.'
    smtpserver.close()


def match_barcode_rule(trello_db, barcode):
    """Finds a barcode rule matching the given barcode.

       Returns the rule if it exists, otherwise returns None."""
    for rule in trello_db.get_all('barcode_rules'):
        if rule['barcode'] == barcode:
            return rule
    return None


def match_synonym_rule(trello_db, desc):
    """Finds a description rule matching the given product description.

       Returns the rule if it exists, otherwise returns None."""
    for rule in trello_db.get_all('synonym_rules'):
        if rule['search_term'] in desc.lower():
            return rule
    return None

# Load list of keywords
with io.open('/var/oscar/keywords.txt', encoding='UTF8', mode='r') as kw_file:
    keywords = [row.strip('\r\n') for row in kw_file.readlines()]

def find_keywords(desc):
    """ Returns keywords in the item description to suggest as short names. """
    return [word for word in keywords if word.lower() in desc.lower()]

def add_grocery_item(trello_api, item, desc=None):
    """Adds the given item to the grocery list (if it's not already present)."""
    # Get the current grocery list
    grocery_board_id = conf.get()['trello_grocery_board']
    all_lists = trello_api.boards.get_list(grocery_board_id)
    grocery_list = [x for x in all_lists if x['name'] == conf.get()['trello_grocery_list']][0]
    cards = trello_api.lists.get_card(grocery_list['id'])
    card_names = [card['name'] for card in cards]

    # Add item if it's not there already
    if item not in card_names:
        print "Adding '{0}' to grocery list.".format(item)
        trello_api.lists.new_card(grocery_list['id'], item, desc)
    else:
        print "Item '{0}' is already on the grocery list; not adding.".format(item)


""" The main script """
trello_api = trello.TrelloApi(conf.get()['trello_app_key'])
trello_api.set_token(conf.get()['trello_token'])
trello_db = trellodb.TrelloDB(trello_api, conf.get()['trello_db_board'])

f = open(conf.get()['scanner_device'], 'rb')
while True:
    print 'Waiting for scanner data...'

    # Wait for binary data from the scanner and then read it
    scan_complete = False
    scanner_data = ''
    while True:
        rlist, _wlist, _elist = select.select([f], [], [], 0.1)
        if rlist != []:
            new_data = ''
            while not new_data.endswith('\x01\x00\x1c\x00\x01\x00\x00\x00'):
                new_data = rlist[0].read(16)
                scanner_data += new_data
            # There are 4 more keystrokes sent after the one we matched against,
            # so we flush out that buffer before proceeding:
            [rlist[0].read(16) for i in range(4)]
            scan_complete = True
        if scan_complete:
            break

    # Parse the binary data as a barcode
    barcode = parse_scanner_data(scanner_data)
    print "Scanned barcode '{0}'.".format(barcode)

    # Match against known barcodes
    barcode_rule = match_barcode_rule(trello_db, barcode)
    if barcode_rule is not None:
        add_grocery_item(trello_api, barcode_rule['item'], barcode_rule['desc'])
        continue

    # This must be a new item, so get a description from the database
    if conf.get()['barcode_api'] == 'zeroapi':
        upc_api = FakeAPI()
    else:
        upc_api = UPCAPI(conf.get()['digiteyes_app_key'], conf.get()['digiteyes_auth_key'])
    try:
        desc = upc_api.get_description(barcode)
        print "Received description '{0}' for barcode {1}.".format(desc, unicode(barcode))
    except Exception, err:
        # If it's a just a problem contacting the database, we'll make an entry
        # in the log and carry on.
        upc_database_issues = {
            CodeInvalid: "Barcode {} not recognized as a UPC.".format(unicode(barcode)),
            SignatureInvalid: "Unable to contact UPC database because signature is invalid.",
            RequireFunds: "Unable to retrieve from UPC database due to insufficient funds.",
            CodeNotFound: "Barcode {} not found in UPC database.".format(unicode(barcode)),
            requests.exceptions.HTTPError: "Unexpected error while contacting UPC database: \'{}\'".format(err.message)
        }
        if err in upc_database_issues:
            print upc_database_issues[err]
            opp = create_barcode_opp(trello_db, barcode)
            publish_unknown(opp)
            continue
        else:
            raise err

    # Add card with full description
    add_grocery_item(trello_api, desc)

    # Offer to learn a short name for this barcode
    opp = create_barcode_opp(trello_db, barcode, desc)

    suggestions = []

    # Match against description rules
    desc_rule = match_synonym_rule(trello_db, desc)
    if desc_rule is not None:
        suggestions.append(desc_rule['item'])

    # Match against keyword list
    suggestions += find_keywords(desc)

    publish_learning_opp(opp, suggestions)

