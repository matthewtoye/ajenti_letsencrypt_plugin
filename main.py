import pwd
import grp
import os
import logging
import subprocess
import json
import time
import shutil

from string import Template
from shutil import copyfile

from ajenti.api import *
from ajenti.plugins.main.api import SectionPlugin
from ajenti.ui import on
from ajenti.ui.binder import Binder
from ajenti.util import platform_select

from pprint import pprint

class Settings (object):
    def __init__(self):
        self.basedir = platform_select(
            debian='/etc/dehydrated/',
            centos='/etc/dehydrated/',
            mageia='/etc/dehydrated/',
            freebsd='/usr/local/etc/dehydrated/',
            arch='/etc/dehydrated/',
            osx='/opt/local/etc/dehydrated/',
        )
 
        self.nginx_sites_available = platform_select(
            debian='/etc/nginx/sites-available/',
            centos='/etc/nginx.custom.d/',
            mageia='/etc/nginx.custom.d/',
            freebsd='/usr/local/etc/nginx.custom.d/',
            arch='/etc/nginx/sites-available/',
            osx='/opt/local/etc/nginx/',
        )

        self.nginx_sites_enabled = platform_select(
            debian='/etc/nginx/sites-enabled/',
            centos='/etc/nginx.custom.d/',
            mageia='/etc/nginx.custom.d/',
            freebsd='/usr/local/etc/nginx.custom.d/',
            arch='/etc/nginx/sites-available/',
            osx='/opt/local/etc/nginx/',
        )
        
        self.crontab_dir = platform_select(
            debian='/etc/cron.d/',
            centos='/etc/cron.d/',
            mageia='/etc/cron.d/',
            freebsd='/usr/local/etc/cron.d/',
            arch='/etc/cron.d/',
            osx='/opt/local/etc/cron.d/',
        )
         
        self.scriptname = 'dehydrated'
        self.wellknown = '/var/www/dehydrated/'
        self.domains = 'example.com sub.example.com sub2.example.com\notherdomain.net sub.otherdomain.net\nmydomain.org blog.mydomain.org home.mydomain.org'
        self.cronjob = False
        self.certs = []
        self.cronfile = 'dehydrated'
        self.results = ''
        self.configname = 'config'
        self.domainfile = 'domains.txt'
        self.nginx_config = 'letsencrypt_check.conf'

class CertificateInfo(object):
    def __init__(self, owner, bdir, entry, sslchain, sslcert, sslfull, sslpriv):
        self.name = entry
        self.owner = owner
        self.dir = bdir
        self.sslchain = sslchain
        self.sslcert = sslcert
        self.sslfull = sslfull
        self.sslpriv = sslpriv
    
@plugin
class LetsEncryptPlugin (SectionPlugin):
    pwd = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
    has_domains = False

    def init(self):
        self.title = 'LetsEncrypt'  # those are not class attributes and can be only set in or after init()
        self.icon = 'lock'
        self.category = 'Security'

        self.append(self.ui.inflate('letsencrypt:main'))
        
        self.settings = Settings()
        self.binder = Binder(self.settings, self)

        def delete_cert(cert, c):
            logging.debug('removed cert %s' % cert.name)
            c.remove(cert)
            logging.debug("cert info: %s %s" % (cert.dir, cert.name))
            shutil.rmtree(cert.dir)
 
        def on_cert_bind(o, c, cert, u):
            cert.__old_name = cert.name

        self.find('certs').delete_item = delete_cert
        self.find('certs').post_item_bind = on_cert_bind
        
    def on_page_load(self):
        self.refresh()
        
    def refresh(self):
        filepath = self.settings.basedir + self.settings.domainfile
        domains = ''
        
        if os.path.isfile(filepath):
            with open(filepath) as f:
                domains = f.readlines()
            domains = [x.strip() for x in domains]
            domains = "\n".join(domains)
        else:
            domains =  self.find('domains').value
       
        cron = self.check_cron()
        self.find('domains').value = str(domains)
        self.find('cronjob').value = cron
        #self.settings.certs = [CertificateInfo(self, self.settings.basedir + '/certs/' + x + '/', x) for x in self.list_available()]

        available_domains = self.list_available()
        temp_obj = []
        logging.debug("item: %s type: %s" % (available_domains, type(available_domains)))
        if available_domains:    
            for x in available_domains:
            
                #cert chain
                my_ssl_chain = self.settings.basedir + '/certs/' + x + '/chain.pem'
                if os.path.isfile(my_ssl_chain):
                    with open(my_ssl_chain, 'r') as myfile:
                        my_ssl_chain=myfile.read().replace('\n', '')
                else:
                    my_ssl_chain = "MISSING"
                
                #public key
                my_ssl_cert = self.settings.basedir + '/certs/' + x + '/cert.pem'
                if os.path.isfile(my_ssl_cert):
                    with open(my_ssl_cert, 'r') as myfile:
                        my_ssl_cert=myfile.read().replace('\n', '')
                else:
                    my_ssl_cert = "MISSING"
                    
                #public key and cert chain
                my_ssl_fullcert = self.settings.basedir + '/certs/' + x + '/fullchain.pem'
                if os.path.isfile(my_ssl_fullcert):
                    with open(my_ssl_fullcert, 'r') as myfile:
                        my_ssl_fullcert=myfile.read().replace('\n', '')
                else:
                    my_ssl_fullcert = "MISSING"
                    
                #private key
                my_ssl_key = self.settings.basedir + '/certs/' + x + '/privkey.pem'
                if os.path.isfile(my_ssl_key):
                    with open(my_ssl_key, 'r') as myfile:
                        my_ssl_key=myfile.read().replace('\n', '')
                else:
                    my_ssl_key = "MISSING"
                    
                temp_obj.append(CertificateInfo(self, self.settings.basedir + '/certs/' + x + '/', x, my_ssl_chain, my_ssl_cert, my_ssl_fullcert, my_ssl_key))
                
            self.settings.certs = temp_obj
        else:
            logging.debug("NO DOMAINS AVAILABLE")
            
        logging.debug("refresh certs value: %s" % self.settings.certs)
        self.binder.setup(self.settings).populate()
        
    def list_available(self):
        if not os.path.isdir(self.settings.basedir + "certs"):
            return False
            
        return [x for x in sorted(os.listdir(self.settings.basedir + "certs")) if
                os.path.isdir(os.path.join(self.settings.basedir + "certs", x))]

    def get_path(self, entry):
        return os.path.abspath(os.path.join(self.settings.basedir, entry))
        
    def write_domain_file(self):
        filepath = self.settings.basedir + self.settings.domainfile
        if not self.find('domains').value:
            self.context.notify('info', 'No domains specified')
            self.has_domains = False
            return

        file = open(filepath, 'w')
        if file.write(self.find('domains').value) is None:
            self.has_domains = True
        else:
            self.context.notify('error', 'Domain file write error')
        file.close()

    def read_domain_file(self):
        filepath = self.settings.basedir + self.settings.domainfile
        if not open(filepath):
            self.context.notify('error', 'Domain file could not be read')

        file = open(filepath)
        with file as f:
            lines = f.readlines()
        return lines

    def create_folders(self):
        uid = pwd.getpwnam("www-data").pw_uid
        gid = grp.getgrnam("www-data").gr_gid

        if not os.path.exists(self.settings.basedir):
            os.makedirs(self.settings.basedir)
            os.chown(self.settings.basedir, uid, gid)
        if not os.path.exists(self.settings.wellknown):
            os.makedirs(self.settings.wellknown)
            os.chown(self.settings.wellknown, uid, gid)

    def create_custom_config(self):
        template = """
        BASEDIR=$basedir
        WELLKNOWN=$wellknown
        """
        dict = {
            'basedir': self.settings.basedir,
            'wellknown': self.settings.wellknown
        }

        filepath = self.settings.basedir + self.settings.configname
        file = open(filepath, 'w')
        src = Template( template )
        if file.write(src.safe_substitute(dict)) is not None:
            self.context.notify('info', 'Letsencrypt error')
        file.close()
        
    def cleanup_oldfiles(self):
        filepath1 = self.settings.nginx_sites_enabled + self.settings.nginx_config
        filepath2 = self.settings.nginx_sites_available + self.settings.nginx_config
        filepath3 = self.settings.basedir + self.settings.configname
        filepath4 = self.settings.basedir + self.settings.domainfile
        
        if os.path.isfile(filepath1):
            os.remove(filepath1)
        if os.path.isfile(filepath2):
            os.remove(filepath2)
        if os.path.isfile(filepath3):
            os.remove(filepath3)
        if os.path.isfile(filepath4):
            os.remove(filepath4)
        
        self.context.notify('info', 'removed all local files')  
        
    def create_wellknown(self):
        if not self.check_nginx_custom_dir():
            self.context.notify('info', 'nginx_custom_dir() is not valid: %s')
            return False

        template = """
            server {
                server_name $domains;
                listen *:80;
                location $location {
                    alias $alias;
                }
            }
        """
        
        dict = {
            'location': '/.well-known/acme-challenge',
            'alias': self.settings.wellknown,
            'domains': " ".join(self.read_domain_file())
        }
        filepath = self.settings.nginx_sites_available + self.settings.nginx_config
        filepath2 = self.settings.nginx_sites_enabled + self.settings.nginx_config
        
        file = open(filepath, 'w')
        src = Template( template )
        if file.write(src.safe_substitute(dict)) is not None:
            self.context.notify('info', 'WELLKNOWN config write error')
        file.close()
        
        if os.path.isfile(filepath2):
            #self.context.notify('info', 'symlink already exists :)')
            return True
            
        os.symlink(filepath, filepath2)

    def create_cron(self):
        file = open(self.settings.crontab_dir + self.settings.cronfile, 'w')
        template = "0 0 1 * * " + self.pwd + 'libs/letsencrypt.sh/letsencrypt.sh -c'
        if not file.write(template):
            self.context.notify('info', 'Cron job error')
        file.close()

    def remove_cron(self):
        if os.path.isfile(self.settings.crontab_dir + self.settings.cronfile):
            if os.remove(self.settings.crontab_dir + self.settings.cronfile):
                return True
            else:
                self.context.notify('info', 'Cron remove error')
                return False

    def check_cron(self):
        if os.path.isfile(self.settings.crontab_dir + self.settings.cronfile):
            return True
        return False

    def check_nginx_custom_dir(self):
        if not os.path.exists(self.settings.nginx_sites_available):
            os.makedirs(self.settings.nginx_sites_available)
            
        #self.context.notify('info', 'NGINX sites available directory exists')
        if not os.path.exists(self.settings.nginx_sites_enabled):
            os.makedirs(self.settings.nginx_sites_enabled)
        
        #self.context.notify('info', 'NGINX sites enabled directory exists')

        if os.path.exists(self.settings.nginx_sites_available) and os.path.exists(self.settings.nginx_sites_enabled):
            return True
        
        self.context.notify('error', 'One or more nginx directories is incorrect')

    def request_certificates(self, register):
        filepath = self.settings.basedir + self.settings.scriptname
        params = [filepath, '-c']
        if self.find('renewal').value:
            params.append('--force')
            
        if register:
            params = [filepath, '--register', '--accept-terms']
       
        p = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        #mysplit = out.split("\n")
        #self.context.notify('info', len(mysplit))
        logging.debug(out)
        #for i in mysplit:
        #    logging.debug(str(i))
        if out:
            self.context.notify('info', 'Success!')
        if err:
            self.context.notify('info', 'ERROR: ' + err)
            
    def restart_nginx(self):
        self.context.notify('info', 'Restarting Nginx')
        command = ['/usr/sbin/service', 'nginx', 'restart'];
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()

    def save(self):
        self.binder.update()
        self.binder.populate()
        self.create_folders()
        self.write_domain_file()

        if not self.has_domains:
            self.cleanup_oldfiles()
            self.restart_nginx()
            return

        self.create_custom_config()
        self.create_wellknown()

        if self.settings.cronjob:
            self.create_cron()
        else:
            self.remove_cron()
        self.restart_nginx()
    
    @on('tabs', 'switch')
    def tab_switched(self):
        self.refresh()
        
    @on('save', 'click')
    def save_button(self):
        self.save()
    
    @on('test', 'click')
    def test_button(self):
        logging.debug("TEST: %s" % self.list_available())
        
    @on('request', 'click')
    def request_button(self):
        self.save()
        time.sleep(5)
        if not os.path.exists(self.settings.basedir + "accounts"):
            self.context.notify('error', 'No accounts directory found, need to register')
            self.request_certificates(True)
            
        if os.path.exists(self.settings.basedir + "accounts"):
            self.request_certificates(False)
      