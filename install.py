#!/usr/bin/env python
"""Initial setup script for Oscar. Run it on the device where Oscar will be running.

   https://github.com/danslimmon/oscar"""

import os
import io
import sys
import subprocess
import re


def run_command(command):
    p = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in iter(p.stdout.readline, ''):
        print line,


print "Let's set up Oscar."
print
print "This script is tested on Raspbian. If you're running something else, I'd"
print "love a pull request to adapt it to your situation!"
print


######################################## Initial checks
if os.getuid() != 0:
    print "This script should be run as root on the target device. Aborting."
    print
    sys.exit(1)


######################################## Digit-Eyes
print "You need accounts with a few APIs to use Oscar. First of all,"
print "go to"
print
print "    http://www.digit-eyes.com"
print
print "and sign up for an account there. This is the database that Oscar uses to"
print "match barcodes with names of products. When you're ready, enter your"
print "API credentials. They can be found on the \"My Account\" page."
print
digiteyes_app_key = raw_input('App Key ("K" Code): ')
digiteyes_auth_key = raw_input('Authorization Key ("M" Code): ')


######################################## Trello
trello_app_key = '95be613d21fcfa29f3580cc3ea4314cf'
print
print "You'll also need a Trello account. You can sign up at:"
print
print "    https://trello.com"
print
print "Once you have an account, go to this URL:"
print
print "    https://trello.com/1/authorize?key={0}&name=oscar&expiration=never&response_type=token&scope=read,write".format(trello_app_key)
print
print "You'll be shown a 'token'; enter it below."
print
trello_token = raw_input('Token: ')
print
print "Alright, now, we haven't yet found a way to create boards via the Trello"
print "API, so would you be a dear and create two Trello boards?"
print
print "First create a board called 'Groceries', and enter its URL here:"
print
trello_grocery_board_url = raw_input('Grocery Board URL: ')
print
print "And now create a board called 'oscar_db', and enter its URL here:"
print
trello_db_board_url = raw_input('Trello DB board URL: ')

# Get the board IDs from their URLs
m = re.search('/b/([^/]+)', trello_grocery_board_url)
trello_grocery_board = m.group(1)
m = re.search('/b/([^/]+)', trello_db_board_url)
trello_db_board = m.group(1)
trello_grocery_list = 'Groceries'

######################################## Communication
print
print "Oscar can email or text you when it scans something it doesn't recognize. This"
print "gives you the opportunity to teach Oscar about items you frequently buy."
print "Please choose whether you want oscar to email or text you by typing 'email' or 'text'."
print
communication_method = raw_input("Communication method ('email' or 'text'): ")
while communication_method not in ['email', 'text']:
    communication_method = raw_input("Please input 'email' or 'text': ")

gmail_user = ''
gmail_password = ''
email_dest = ''
twilio_src = ''
twilio_sid = ''
twilio_token = ''
twilio_dest = ''
if communication_method == 'email':
    ######################################## Email
    print
    print "To enable this functionality using email as the communication method, "
    print "you need an account with GMail:"
    print
    print "    https://mail.google.com/"
    print
    print "If you want to, you can sign up for a GMail account and enter your"
    print "information below. If not, no sweat: just leave the input blank. You"
    print "can always come back and modify Oscar's config file later."
    print
    gmail_user = raw_input('GMail Email Address: ')
    if gmail_user != '':
        gmail_password = raw_input('GMail Password: ')
        email_dest = raw_input('Destination email (the address you want emailed): ')
    else:
        gmail_password = ''
        email_dest = ''
else:
    ######################################## Twilio
    print
    print "To enable this functionality using text as the communication method, "
    print "you need an account with Twilio:"
    print
    print "    https://www.twilio.com/"
    print
    print "If you want to, you can sign up for a Twilio account and enter your"
    print "information below. If not, no sweat: just leave the input blank. You"
    print "can always come back and modify Oscar's config file later."
    print
    twilio_src = raw_input('Twilio number: ')
    if twilio_src != '':
        twilio_sid = raw_input('Twilio SID: ')
        twilio_token = raw_input('Twilio token: ')
        twilio_dest = raw_input('Destination number (the number you want texted): ')
    else:
        twilio_sid = ''
        twilio_token = ''
        twilio_dest = ''
    # Remove any non-digits from phone numbers
    twilio_src = re.sub('\D', '', twilio_src)
    twilio_dest = re.sub('\D', '', twilio_dest)


######################################## Scanner
print
print "And lastly, enter the path to your scanner device. If you don't know"
print "this and you're using a Raspberry Pi, the default should be fine."
print
scanner_device = raw_input('Scanner device [/dev/input/event0]: ')
if scanner_device == '':
    scanner_device = '/dev/input/event0'


######################################## Dependencies
print
print "Now we need to install some dependencies. This can take upwards of an"
print "hour, since it involves compiling stuff. Ready? Press <enter> when"
print "you're ready. Press 'Ctrl+C' to cancel."
print
raw_input('Press enter when ready: ')


######################################## oscar_scan dependencies
run_command('apt-get install python-setuptools')
run_command('easy_install pip')
run_command('pip install PyYAML trello twilio')


######################################## oscar_web dependencies
run_command('wget http://node-arm.herokuapp.com/node_latest_armhf.deb')
run_command('dpkg -i node_latest_armhf.deb')


######################################## Dependencies of both
run_command('apt-get update')
run_command('apt-get install git supervisor')


######################################## Oscar itself
os.chdir('/var')
run_command('git clone https://github.com/bergkoet/oscar.git')
os.chdir('/var/oscar/web')
run_command('npm install')


######################################## Create the appropriate Trello lists
import trello
trello_api = trello.TrelloApi(trello_app_key)
trello_api.set_token(trello_token)
# Grocery list
trello_api.boards.new_list(trello_grocery_board, 'Groceries')
# oscar_db lists
for db_list in ['synonym_rules', 'keywords', 'barcode_rules', 'learning_opportunities']:
    trello_api.boards.new_list(trello_db_board, db_list)


######################################## Create the default synonym rules
new_rules = [
    {'search_term': 'ale', 'item': 'beer'},
    {'search_term': 'ipa', 'item': 'beer'},
    {'search_term': 'lager', 'item': 'beer'},
    {'search_term': 'stout', 'item': 'beer'},
    {'search_term': 'soymilk', 'item': 'soy milk'}
]
os.chdir('/var/oscar')
from lib import trellodb
trello_db = trellodb.TrelloDB(trello_api, trello_db_board)
for rule in new_rules:
    trello_db.insert('synonym_rules', rule)


######################################## Upload default keyword list
with io.open('keywords.txt', encoding='UTF8', mode='r') as kw_file:
    keywords = [row.strip('\r\n') for row in kw_file.readlines()]
print "Uploading keywords; this may take several minutes..."
for word in keywords:
    trello_db.insert('keywords', word)
print "Upload complete!"


######################################## Oscar configs
oscar_yaml = open('/etc/oscar.yaml', 'w')
oscar_yaml.write('''---
port: 80
scanner_device: '{scanner_device}'

communication_method: '{communication_method}'

gmail_user: '{gmail_user}'
gmail_password: '{gmail_password}'
email_dest: '{email_dest}'

twilio_src: '{twilio_src}'
twilio_dest: '{twilio_dest}'
twilio_sid: '{twilio_sid}'
twilio_token: '{twilio_token}'

trello_app_key: '{trello_app_key}'
trello_token: '{trello_token}'
trello_grocery_board: '{trello_grocery_board}'
trello_grocery_list: '{trello_grocery_list}'
trello_db_board: '{trello_db_board}'

digiteyes_app_key: '{digiteyes_app_key}'
digiteyes_auth_key: '{digiteyes_auth_key}'

# possible values: 'digiteyes' or 'zeroapi'
barcode_api: digiteyes
'''.format(**locals()))
oscar_yaml.close()

sup_oscar_scan = open('/etc/supervisor/conf.d/oscar_scan.conf', 'w')
sup_oscar_scan.write('''[program:oscar_scan]

command=python /var/oscar/scan.py
stdout_logfile=/var/log/supervisor/oscar_scan.log
redirect_stderr=true''')
sup_oscar_scan.close()

sup_oscar_web = open('/etc/supervisor/conf.d/oscar_web.conf', 'w')
sup_oscar_web.write('''[program:oscar_web]

command=/usr/local/bin/node --debug /var/oscar/web/app.js
directory=/var/oscar/web
stdout_logfile=/var/log/supervisor/oscar_web.log
redirect_stderr=true''')
sup_oscar_web.close()

run_command('supervisorctl reload')

print
print '############################################################'
print
print 'Done! Your new grocery list can be found at:'
print
print '    {0}'.format(trello_grocery_board_url)
print
print 'If everything worked, then you should be able to start scanning'
print 'barcodes with oscar. Check out the logs of the scanner process and'
print 'the web app, respectively, at'
print
print '    /var/log/supervisor/oscar_scan.log'
print '    /var/log/supervisor/oscar_web.log'
print
print 'And report any bugs at https://github.com/danslimmon/oscar/issues.'
print
print 'To add new product description keywords, the current method is to'
print 'edit the oscar_db board directly. This should change soon with #5.'
print
print 'Enjoy!'
