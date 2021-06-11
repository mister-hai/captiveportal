# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
################################################################################
##  Pybash-sh; CaptivePortal() : No SQL Edition - Vintage 2021 Python 3.9     ##
################################################################################                
#  YOU HAVE TO PROVIDE THE MODULES YOU CREATE AND THEY MUST FIT THE SPEC      ##
#                                   
#     You can fuck up the backend all you want but if I can't run the module 
#     you provide, nor understand it, you have to then follow the original 
#     terms of the GPLv3 and open source all modified code so I can see 
#     what's going on. 
# 
# Licenced under GPLv3-modified                                               ##
# https://www.gnu.org/licenses/gpl-3.0.en.html                                ##
#                                                                             ##
# The above copyright notice and this permission notice shall be included in  ##
# all copies or substantial portions of the Software.                         ##
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################
"""
This pybashy file uses the following configuration
    pybashy spec:
        - 
        - no config file
        - no argparser
        - monolithic

"""

TESTING = True
import sys,os
import logging
import pkgutil
import inspect
import traceback
import threading
import subprocess
from pathlib import Path
from importlib import import_module
from sqlalchemy import create_engine
#from sqlalchemy import inspect
from sqlalchemy.pool import StaticPool
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils import database_exists
from flask import Flask, render_template, Response, Request ,Config
try:
    import colorama
    from colorama import init
    init()
    from colorama import Fore, Back, Style
    if TESTING == True:
        COLORMEQUALIFIED = True
except ImportError as derp:
    print("[-] NO COLOR PRINTING FUNCTIONS AVAILABLE, Install the Colorama Package from pip")
    COLORMEQUALIFIED = False

################################################################################
##############                      VARS                       #################
################################################################################
basic_items  = ['__name__', 'steps','success_message', 'failure_message', 'info_message']
# we are going to do an inheritance connection to apply the user data to the user table
list_of_db_tables   = ["Users", "UserData"]
db_is_initialized   = bool
db_is_populated     = bool
LOGLEVEL            = 'DEV_IS_DUMB'
LOGLEVELS           = [1,2,3,'DEV_IS_DUMB']
log_file            = 'pybashy'
logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', filemode='w')
logger              = logging.getLogger()
script_cwd          = Path().absolute()
script_osdir        = Path(__file__).parent.absolute()

redprint          = lambda text: print(Fore.RED + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
blueprint         = lambda text: print(Fore.BLUE + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
greenprint        = lambda text: print(Fore.GREEN + ' ' +  text + ' ' + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
yellow_bold_print = lambda text: print(Fore.YELLOW + Style.BRIGHT + ' {} '.format(text) + Style.RESET_ALL) if (COLORMEQUALIFIED == True) else print(text)
makeyellow        = lambda text: Fore.YELLOW + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else text
makered           = lambda text: Fore.RED + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
makegreen         = lambda text: Fore.GREEN + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
makeblue          = lambda text: Fore.BLUE + ' ' +  text + ' ' + Style.RESET_ALL if (COLORMEQUALIFIED == True) else None
debug_message     = lambda message: logger.debug(blueprint(message)) 
info_message      = lambda message: logger.info(greenprint(message))   
warning_message   = lambda message: logger.warning(yellow_bold_print(message)) 
error_message     = lambda message: logger.error(redprint(message)) 
critical_message  = lambda message: logger.critical(yellow_bold_print(message))

is_method          = lambda func: inspect.getmembers(func, predicate=inspect.ismethod)

def error_printer(message):
    exc_type, exc_value, exc_tb = sys.exc_info()
    trace = traceback.TracebackException(exc_type, exc_value, exc_tb) 
    try:
        redprint( message + ''.join(trace.format_exception_only()))
        #traceback.format_list(trace.extract_tb(trace)[-1:])[-1]
        blueprint('LINE NUMBER >>>' + str(exc_tb.tb_lineno))
    except Exception:
        yellow_bold_print("EXCEPTION IN ERROR HANDLER!!!")
        redprint(message + ''.join(trace.format_exception_only()))
################################################################################
##############                      CONFIG                     #################
################################################################################
TEST_DB            = 'sqlite://'
DATABASE           = "captive portal"
LOCAL_CACHE_FILE   = 'sqlite:///' + DATABASE + ".db"
DATABASE_FILENAME  = DATABASE + '.db'

if database_exists(LOCAL_CACHE_FILE) or os.path.exists(DATABASE_FILENAME):
    DATABASE_EXISTS = True
else:
    DATABASE_EXISTS = False        
  
class Config(object):
# TESTING = True
# set in the std_imports for a global TESTING at top level scope
    SQLALCHEMY_DATABASE_URI = LOCAL_CACHE_FILE
    SQLALCHEMY_TRACK_MODIFICATIONS = False

try:
    engine = create_engine(LOCAL_CACHE_FILE , connect_args={"check_same_thread": False},poolclass=StaticPool)
    PybashyDatabase = Flask(__name__ )
    PybashyDatabase.config.from_object(Config)
    PybashyDB = SQLAlchemy(PybashyDatabase)
    PybashyDB.init_app(PybashyDatabase)
    if TESTING == True:
        PybashyDB.metadata.clear()
except Exception:
    exc_type, exc_value, exc_tb = sys.exc_info()
    tb = traceback.TracebackException(exc_type, exc_value, exc_tb) 
    error_message("[-] Database Initialization FAILED \n" + ''.join(tb.format_exception_only()))

class JSONCommand(PybashyDB.Model):
    __tablename__       = 'CommandSets'
    #__table_args__      = {'extend_existing': True}
    id                  = PybashyDB.Column(PybashyDB.Integer,
                                          index         = True,
                                          unique        = True,
                                          autoincrement = True)
    command_name                  = PybashyDB.Column(PybashyDB.String(256), primary_key   = True)                                          
    payload                       = PybashyDB.Column(PybashyDB.Text)#,
                                                     #primary_key   = True)
    notes                         = PybashyDB.Column(PybashyDB.Text)

    def __repr__(self):
        return '''=========================================
CommandSet Name : {}
CommandSet_JSON : {} 
Notes           : {}
'''.format(self.command_name,
            self.payload,
            self.notes
        )
#########################################################
###                    User MODEL
#########################################################
class CaptiveClient(PybashyDB.Model):
    __tablename__       = 'Hosts'
    #__table_args__      = {'extend_existing': True}
    id                  = PybashyDB.Column(PybashyDB.Integer,
                                          primary_key   = True,
                                          index         = True,
                                          unique        = True,
                                          autoincrement = True)
    Hostname                  = PybashyDB.Column(PybashyDB.String(256))                                          
    username                  = PybashyDB.Column(PybashyDB.String(256))
    password                  = PybashyDB.Column(PybashyDB.String(256))
    macaddr                   = PybashyDB.Column(PybashyDB.String(32))
    ipaddress                 = PybashyDB.Column(PybashyDB.String(32))
    email                     = PybashyDB.Column(PybashyDB.String(256))
    isauthenticated           = PybashyDB.Column(PybashyDB.Bool)
    isactive                  = PybashyDB.Column(PybashyDB.Bool)

    def __repr__(self):
        return '''=========================================
Username : {}
Password : {} 
Email    : {}
'''.format(self.username,
            self.password,
            self.email,
        )
    def is_active(self):
        """"""
        return self.active

    def logout(self):
        ''''''
        self.active = False

    def login(self):
        ''''''
        self.active = True 

    def get_id(self):
        #"""Return the email address to satisfy Flask-Login's requirements."""
        #return self.email
        pass
    
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

################################################
###             DATABASE FUNCTIONS
#########################################################
def add_to_db(thingie):
    """
    Takes SQLAchemy model Objects 
    For updating changes to Class_model.Attribute using the form:
        Class_model.Attribute = some_var 
        add_to_db(some_var)
    """
    try:
        PybashyDB.session.add(thingie)
        PybashyDB.session.commit
        redprint("=========Database Commit=======")
        greenprint(thingie)
        redprint("=========Database Commit=======")
    except Exception as derp:
        print(derp)
        print(makered("[-] add_to_db() FAILED"))

def ReturnClientVar(client, var):
    ''''''
    return client.query.filter_by(var)

def ReturnClientById(idnum):
    PybashyDB.session.query(idnum)

def queryusers(username):
    PybashyDb.session.query(CaptiveClient).filter_by(username = username)

def add_cmd_to_db(cmd_to_add):
    """
    "name" is the primary key of DB, is unique
    """
    try:
        if PybashyDB.session.query(cmd_to_add).filter_by(name=cmd_to_add.name).scalar() is not None:
            info_message('[+] Duplicate Entry Avoided : ' + cmd_to_add.name)
        # and doesnt get added
        else: # and it does if it doesnt... which works out somehow ;p
            PybashyDB.session.add(cmd_to_add)
            info_message('[+] Command Added To Database : ' + cmd_to_add.name)
    except Exception:
        error_printer("[-] add_cmd_to_db() FAILED")

def DoesUsernameExist(username):
    """
    "name" is the primary key of DB, is unique
    """
    try:
        if PybashyDB.session.query(CaptiveClient).filter_by(name=username).scalar() is not None:
            info_message('[-] CaptiveUser {} Does Not Exist'.format(username))
            return None
        else:
            info_message('[-] CaptiveUser {} Exists'.format(username))
            return True
    except Exception:
        error_printer("[-] DoesUsernameExist() FAILED")

def update_db():
    try:
        PybashyDB.session.commit()
    except Exception as derp:
        print(derp.with_traceback)
        print(makered("[-] Update_db FAILED"))

def DoesUsernameExist(username):
    """
    "name" is the primary key of DB, is unique
    """
    try:
        if PybashyDB.session.query(CaptiveClient).filter_by(name=username).scalar() is not None:
            info_message('[-] CaptiveUser {} Does Not Exist'.format(username))
            return None
        else:
            info_message('[-] CaptiveUser {} Exists'.format(username))
            return True
    except Exception:
        error_printer("[-] DoesUsernameExist() FAILED")

def does_exists(self,Table, Row):
    try:
        if PybashyDB.session.query(Table.id).filter_by(name=Row).first() is not None:
            info_message('[+] Client {} Exists'.format(Row))
            return True
        else:
            return False        
    except Exception:
        error_printer('[-] Database VERIFICATION FAILED!')

#########################################################
###         INITIALIZE DATABASE TABLES
#########################################################
testuser = CaptiveClient(Hostname= "ChristmasParty",
                         username = "johnmclaine",
                         password= "machinegun",
                         macaddr = "de:ad:be:ef:ca:fe",
                         email   = "1badasscop@nakatomi.plaza",
                         notes   = "treat with respect"
                       )

try:
    PybashyDB.create_all()
    PybashyDB.session.commit()
except Exception:
    exc_type, exc_value, exc_tb = sys.exc_info()
    tb = traceback.TracebackException(exc_type, exc_value, exc_tb) 
    error_message("[-] Database Table Creation FAILED \n" + ''.join(tb.format_exception_only()))

greenprint("[+] Database Loaded!")