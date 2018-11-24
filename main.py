import pwd
import grp
import os
import io
import logging
import subprocess
import json
import time
import shutil
import collections
import re
import sys
import threading
import pip

from string import Template
from shutil import copyfile

try:
    from nginxparser import load
    from nginxparser import dumps                     
except ImportError:
    logging.debug("no nginxparser module")

from ajenti.api import *
from ajenti.plugins.main.api import SectionPlugin
from ajenti.ui import on
from ajenti.ui.binder import Binder
from ajenti.util import platform_select

from pprint import pprint
linebuffer=[]

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
        self.cronjob = False
        self.output = "IT WORKS MOFO"
        self.dependencies_met = False
        self.certs = []
        self.domains = []
        self.cronfile = 'dehydrated'
        self.results = ''
        self.configname = 'config'
        self.domainfile = 'domains.txt'
        self.nginx_config = 'letsencrypt_check.conf'

class CertificateInfo(object):
    def __init__(self, owner, bdir, entry, date, sslchain, sslcert, sslfull, sslpriv):
        self.name = entry
        self.owner = owner
        self.date = date
        self.dir = bdir
        self.sslchain = sslchain
        self.sslcert = sslcert
        self.sslfull = sslfull
        self.sslpriv = sslpriv

class DomainsInfo(object):
    name = 'new.domain'
    
    def __init__(self, owner, entry, subs):
        self.owner = owner
        self.name = entry
        self.subdomains = subs
        
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

        def delete_domain(domain, c):
            logging.debug('removed domain %s' % domain.name)
            c.remove(domain)
            logging.debug("domain info: %s %s" % (domain.subdomains, domain.name))
            self.save()
            
        def delete_cert(cert, c):
            logging.debug('removed cert %s' % cert.name)
            c.remove(cert)
            logging.debug("cert info: %s %s" % (cert.dir, cert.name))
            shutil.rmtree(cert.dir)

        def on_domain_bind(o, c, domain, u):
            domain.__old_name = domain.name

        def on_cert_bind(o, c, cert, u):
            cert.__old_name = cert.name

        def new_domain(c):
            name = 'domain.com'
            subdomains = 'www.domain.com\nblog.domain.com'
            return DomainsInfo(self, name, subdomains)
            
        self.find('certs').delete_item = delete_cert
        self.find('certs').post_item_bind = on_cert_bind
        self.find('domains').new_item = new_domain
        self.find('domains').delete_item = delete_domain
        self.find('domains').post_item_bind = on_domain_bind
     
    def fix_dependencies(self):
        if self.settings.dependencies_met is True:
            return
        
        changes = False
        
        # Install dehyrated (this is how we communicate with letsencrpyt)
        if not os.path.isfile(self.settings.basedir + self.settings.scriptname):
            self.context.notify('info', 'Fixing dehydrated dependency')
            changes = True
            
            if self.git_clone('https://github.com/lukas2511/dehydrated.git', self.settings.basedir):
                logging.debug("cloning of dehydrated successful")
                changes = False
        
        # Install nginxparser (this is how we edit nginx config files)
        installed_mods = sorted(["%s==%s" % (i.key, i.version) for i in pip.get_installed_distributions()])
        
        if "nginxparser" not in str(installed_mods):
            self.context.notify('info', 'Fixing nginxparser dependency')
            changes = True
            
            if self.git_clone('https://github.com/fatiherikli/nginxparser', '~/'):
                logging.debug("cloning of nginxparser successful.. installing..")
                
                command = ['python', 'setup.py', 'install'];
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/root/nginxparser/')
                out, err = p.communicate()
                
                installed_mods = sorted(["%s==%s" % (i.key, i.version) for i in pip.get_installed_distributions()])
                if "nginxparser" not in str(installed_mods):
                    logging.debug("Something went wrong with installing nginxparser..")
                else:
                    logging.debug("Installed nginxparser correctly.. importing modules..")
                    from nginxparser import load
                    from nginxparser import dumps 
                    changes = False
        
        if changes is False:
            self.settings.dependencies_met = True
            logging.debug("SUCCESSFULLY MET ALL DEPENDENCIES")
            
    def start_thread(self, target, *my_args, **my_keyword_args):
        thr = threading.Thread(target=target, args=my_args, kwargs=my_keyword_args)
        thr.daemon = True
        thr.start()
        return thr
        
    def on_page_load(self):
        self.refresh()
        
    def refresh(self):
        self.fix_dependencies()
        
        filepath = self.settings.basedir + self.settings.domainfile
        domains_file_read = ''
        
        if os.path.isfile(filepath):
            with open(filepath) as f:
                domains_file_read = f.readlines()
            domains_file_read = [x.strip() for x in domains_file_read]
            domains_file_read = "\n".join(domains_file_read)
        else:
            domains_file_read =  ""
       
        cron = self.check_cron()
        
        mysplit = domains_file_read.split("\n")
        tmp = []
        
        for lines in mysplit:
            mysecondsplit = lines.split(" ")
            main_domain = mysecondsplit.pop(0)
            sub_domains = ""
            
            if len(mysecondsplit) >= 1:
                sub_domains = mysecondsplit
                
            tmp.append(DomainsInfo(self, main_domain, "\n".join(sub_domains)))
            
        self.settings.domains = tmp
        self.find('cronjob').value = cron
  
        available_domains = self.list_available_certs()
        available_files = self.list_enabled_nginx_confs()
        temp_obj = []

        if available_domains:    
            for x in available_domains:
                #expiration date
                my_date = self.settings.basedir + '/certs/' + x + '/expiration.date'
                if os.path.isfile(my_date):
                    with open(my_date, 'r') as myfile:
                        my_date=myfile.read().replace('\n', '')
                else:
                    my_date = "NONE"
                
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
                    
                temp_obj.append(CertificateInfo(self, self.settings.basedir + 'certs/' + x + '/', x, my_date, my_ssl_chain, my_ssl_cert, my_ssl_fullcert, my_ssl_key))
            
            self.settings.certs = temp_obj
        else:
            logging.debug("NO DOMAINS AVAILABLE")
            
        self.binder.setup(self.settings).populate()
    
    def list_enabled_nginx_confs(self):
        if not os.path.isdir(self.settings.nginx_sites_enabled):
            return False
            
        return [x for x in sorted(os.listdir(self.settings.nginx_sites_enabled)) if
                os.path.isfile(os.path.join(self.settings.nginx_sites_enabled, x))]

        
    def list_available_certs(self):
        if not os.path.isdir(self.settings.basedir + "certs"):
            return False
            
        return [x for x in sorted(os.listdir(self.settings.basedir + "certs")) if
                os.path.isdir(os.path.join(self.settings.basedir + "certs", x))]

    def write_domain_file(self):
        filepath = self.settings.basedir + self.settings.domainfile
        if len(self.settings.domains) < 1:
            self.context.notify('info', 'No domains specified')
            self.has_domains = False
            return
        
        final_str = ''

        for domains in self.settings.domains:
            final_str = final_str + domains.name + " "
            
            if domains.subdomains:
                tmp = domains.subdomains.split("\n")
                tmp = " ".join(tmp)
                final_str = final_str + tmp
            final_str = final_str + "\n"
            
        logging.debug("final string %s " % final_str)   
        
        file = open(filepath, 'w')
        if file.write(final_str) is None:
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

    def create_dehydrated_config_file(self):
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
        
    def create_nginx_wellknown_config(self):
        if not self.check_nginx_dir_exists():
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

    # Update Nginx config files to use SSL
    def update_nginx_confs(self):
        available_domains = self.list_available_certs()
        filepath = self.settings.basedir + self.settings.domainfile
        domains = ''
        
        if os.path.isfile(filepath):
            with open(filepath) as f:
                domains = f.readlines()
            domains = [x.strip() for x in domains]
            domains = "\n".join(domains)
        
        mysplit = domains.split("\n")
        
        # Gets all enabled sites
        available_nginx_files = self.list_enabled_nginx_confs()

        for curr_domain in available_domains:
            for curr_nginx_file in available_nginx_files:
                logging.debug("## Use Certs: Checking config file - %s ##" % curr_nginx_file)
                
                if self.settings.nginx_config in curr_nginx_file:
                    logging.debug("Skipping file: %s" % curr_nginx_file)
                    continue
                    
                # Path is to the sites_available directory
                filepath = self.settings.nginx_sites_available + curr_nginx_file
                
                if not os.path.isfile(filepath):
                    logging.debug("File not in sites_available directory.. continuing")
                    continue
                    
                loaded_conf = load(open(filepath))
                
                for servers in loaded_conf:
                    server_conf = servers[1]
                    ssl_true = False
                    listen_position = None
                    server_name_position = None
                    ssl_cert_position = None
                    ssl_cert_key_position = None
                    curr_pos = 0
                    
                    for lines in server_conf:
                        if isinstance(lines[0], str):
                            
                            if 'server_name' in lines[0] and len(lines) > 1:
                                if server_name_position is not None:
                                    logging.debug("There must be more than one server_name_position.. skipping this file because we don't know how to handle it.")
                                    print("CONF %s" % loaded_conf)
                                    break
                                    
                                server_name_position = curr_pos
                                
                            if 'listen' in lines[0] and len(lines) > 1:
                                if listen_position is not None:
                                    listen_position = [listen_position]
                                    listen_position.append(curr_pos)
                                    print("There are multiple listen positions: %s" % listen_position)
                                else:    
                                    listen_position = curr_pos
                            
                            if 'ssl_certificate' in lines[0] and 'ssl_certificate_key' not in lines[0] and len(lines) > 1:
                                if ssl_cert_position is not None:
                                    logging.debug("There must be more than one ssl_certificate.. skipping this file because we don't know how to handle it.")
                                    print("CONF %s" % lines[0])
                                    break
                                    
                                ssl_cert_position = curr_pos
                            
                            if 'ssl_certificate_key' in lines[0] and len(lines) > 1:
                                if ssl_cert_key_position is not None:
                                    logging.debug("There must be more than one ssl_certificate_key.. skipping this file because we don't know how to handle it.")
                                    print("CONF %s" % lines[0])
                                    break
                                    
                                ssl_cert_key_position = curr_pos        
                                
                        curr_pos += 1
                    
                    if listen_position is not None and server_name_position is not None:
                        logging.debug("We have both listen and server name positions: listen position: %s | server_name_position: %s" % (listen_position, server_name_position))
                        
                        found_it = False
                        
                        for domain_list_line in mysplit:
                            if found_it is True:
                                break
                            
                            secondsplit = domain_list_line.split(" ")
                            
                            for domains in secondsplit:
                                logging.debug("CHECKING DOMAIN %s with: %s" % (server_conf[server_name_position][1], domains))
                                if server_conf[server_name_position][1] in domains:
                                    logging.debug("found our domain: %s in the list of domains" % server_conf[server_name_position][1])
                                    found_it = True
                                    break
                                
                        if found_it is False:
                            logging.debug("Server Config does not have any of our domains with SSL certs in the 'server_name' position.. skipping this config.")
                            continue
             
                        # Check if SSL is already setup
                        if ssl_cert_key_position is not None and ssl_cert_position is not None:

                            # Check if ports are setup too
                            if isinstance(listen_position, list):
                                already_setup = False
                                
                                for listens in listen_position:
                                    if "443" in server_conf[listens][1]:
                                        already_setup = True
                                        break
                                
                                if already_setup is True:
                                    logging.debug("This server is already setup for SSL")
                                    continue
                            
                            elif isinstance(listen_position, str):
                                if "443" in server_conf[listens][1]:
                                    continue
                                    
                        # Lets setup SSL now...
                        logging.debug("Attempting to setup SSL for domain: %s" % curr_domain)
                        
                        # Multiple listen calls..
                        if isinstance(listen_position, list):
                            already_setup = False
                                
                            for listens in listen_position:
                                if "443" in server_conf[listens][1]:
                                    already_setup = True
                                    break
                            
                            # Check if ssl port is already set
                            if already_setup is True:
                                logging.debug("Server port already setup for SSL")
                                
                            # 443 not set... set one of the listen calls to 443
                            else:
                                server_conf[listen_position[0]][1]
                                
                                # ssl port set already
                                if "443 ssl" in server_conf[listen_position[0]][1]:
                                    logging.debug("Server port already setup for SSL")
                                    
                                # ssl port not set yet..
                                else:   
                                    if ":" in server_conf[listen_position[0]][1]:
                                        tmp = server_conf[listen_position[0]][1].split(":")
                                        
                                        if tmp[1]:
                                            logging.debug("old port value %s" % server_conf[listen_position[0]][1])
                                            r = re.compile(r"\d{2,5}")
                                            tmp[1] = r.sub("443 ssl", tmp[1])
                                            
                                            server_conf[listen_position[0]][1] = ':'.join(tmp)
                                            logging.debug("new port value: %s" % server_conf[listen_position[0]][1])
                                    else:
                                        logging.debug("old port value: %s" % server_conf[listen_position[0]][1])
                                        r = re.compile(r"\d{2,5}")
                                        tmp = r.sub("443 ssl", server_conf[listen_position[0]][1])
                                        
                                        server_conf[listen_position[0]][1] = tmp
                                        logging.debug("new port value: %s" % server_conf[listen_position[0]][1]) 
                                        
                        # Single listen call..
                        else:
                            
                            # ssl port set already
                            if "443 ssl" in server_conf[listen_position][1]:
                                logging.debug("Server port already setup for SSL")
                                
                            # ssl port not set yet..
                            else:   
                                if ":" in server_conf[listen_position][1]:
                                    tmp = server_conf[listen_position][1].split(":")
                                    
                                    if tmp[1]:
                                        logging.debug("old port value %s" % server_conf[listen_position][1])
                                        r = re.compile(r"\d{2,5}")
                                        tmp[1] = r.sub("443 ssl", tmp[1])
                                        
                                        server_conf[listen_position][1] = ':'.join(tmp)
                                        logging.debug("new port value: %s" % server_conf[listen_position][1])
                                       
                                else:
                                    logging.debug("old port value: %s" % server_conf[listen_position][1])
                                    r = re.compile(r"\d{2,5}")
                                    tmp = r.sub("443 ssl", server_conf[listen_position][1])
                                    
                                    server_conf[listen_position][1] = tmp
                                    logging.debug("new port value: %s" % server_conf[listen_position][1])

                        cert_path = self.settings.basedir + '/certs/' + curr_domain + '/fullchain.pem'
                        cert_key_path = self.settings.basedir + '/certs/' + curr_domain + '/privkey.pem'

                        if ssl_cert_position is None:
                            server_conf.insert(0, ["ssl_certificate", cert_path])
                        else:
                            server_conf[ssl_cert_position][1] = cert_path
                            
                        if ssl_cert_key_position is None:
                            server_conf.insert(1, ["ssl_certificate_key", cert_key_path])
                        else:
                            server_conf[ssl_cert_key_position][1] = cert_key_path

                    file = open(filepath,"w") 
                    file.write(dumps(loaded_conf))
                    file.close()  
                    logging.debug("## FINISHED WITH SETTING UP NGINX WITH CERTS ##")
                    self.context.notify('info', 'Nginx is now using your valid certs.')
                    
    def check_nginx_dir_exists(self):
        if not os.path.exists(self.settings.nginx_sites_available):
            os.makedirs(self.settings.nginx_sites_available)
            
        if not os.path.exists(self.settings.nginx_sites_enabled):
            os.makedirs(self.settings.nginx_sites_enabled)

        if os.path.exists(self.settings.nginx_sites_available) and os.path.exists(self.settings.nginx_sites_enabled):
            return True
        
        self.context.notify('error', 'One or more nginx directories is incorrect')

    def request_certs_helper(self):
        self.save()
        time.sleep(5)
        
        if not os.path.exists(self.settings.basedir + "accounts"):
            self.context.notify('error', 'No accounts directory found, Registering before requesting certs..')
            self.request_certificates(True)
            
        if os.path.exists(self.settings.basedir + "accounts"):
            self.request_certificates(False)
            
    def request_certificates(self, register):
        filepath = self.settings.basedir + self.settings.scriptname
        params = [filepath, '-c']
        out = ""
        
        if self.find('renewal').value:
            params.append('--force')
            
        if register:
            params = [filepath, '--register', '--accept-terms']
        
        self.settings.output = "Disabling currently active SYMLINKS\n"
        self.binder.setup(self.settings).populate()
        
        available_files = self.list_enabled_nginx_confs()
        for curr_nginx_file in available_files:
            
            if self.settings.nginx_config in curr_nginx_file:
                logging.debug("Skipping file: %s" % curr_nginx_file)
                continue
            
            logging.debug("Disabling SYMLINK: %s" % curr_nginx_file)
            
            filepath = self.settings.nginx_sites_enabled + curr_nginx_file
            os.unlink(filepath)
        
        p = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        success = False
        
        while p.poll() is None:
            output = p.stdout.readline()
            logging.debug("%s" % output)
            self.settings.output = output + self.settings.output
            self.binder.setup(self.settings).populate()
            
            if "Creating fullchain.pem" in output or "Skipping renew!" in output:
                success = True
  
        self.settings.output = "Re-enabling SYMLINKS...\n" + self.settings.output
        self.binder.setup(self.settings).populate()
        
        for curr_nginx_file in available_files:
            if not os.path.isfile(self.settings.nginx_sites_enabled + curr_nginx_file):
                filepath1 = self.settings.nginx_sites_available + curr_nginx_file
                filepath2 = self.settings.nginx_sites_enabled + curr_nginx_file
                os.symlink(filepath1, filepath2)    
        
        self.settings.output = "Restarting NGINX once more...\n" + self.settings.output
        self.binder.setup(self.settings).populate()
        self.restart_nginx()
        
        if success is True:
            self.settings.output = "Success creating certificates! Congratulations!\n" + self.settings.output
            self.binder.setup(self.settings).populate()
        else:
            self.settings.output = "Something went wrong. Read logs below.\n" + self.settings.output
            self.binder.setup(self.settings).populate()
            
    def restart_nginx(self):
        self.context.notify('info', 'Restarting Nginx')
        command = ['/usr/sbin/service', 'nginx', 'restart'];
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()

    def git_clone(self, repo, dir):
        logging.debug("Cloning REPO: %s into directory: %s" % (repo, dir))
        
        # GIT automatically makes directories
        command = ['/usr/bin/git', 'clone', repo, dir];
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        
        command = ['/usr/bin/git', 'remote', '-v'];
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=dir)
        out, err = p.communicate()
        
        if repo in out:
            return True
        else:
            return False
            
    def helper(self):        
        installed_mods = sorted(["%s==%s" % (i.key, i.version) for i in pip.get_installed_distributions()])
        
        if "nginxparser" not in str(installed_mods):
            if self.git_clone('https://github.com/fatiherikli/nginxparser', '~/'):
                logging.debug("cloning of nginxparser successful.. installing..")
                
                command = ['python', 'setup.py', 'install'];
                p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/root/nginxparser/')
                out, err = p.communicate()
                
                installed_mods = sorted(["%s==%s" % (i.key, i.version) for i in pip.get_installed_distributions()])
                if "nginxparser" not in str(installed_mods):
                    logging.debug("Something went wrong with installing nginxparser..")
            
    def save(self):
        self.binder.update()
        self.binder.populate()
        self.create_folders()
        self.write_domain_file()

        if not self.has_domains:
            
            self.cleanup_oldfiles()
            self.restart_nginx()
            return

        self.create_dehydrated_config_file()
        self.create_nginx_wellknown_config()

        if self.settings.cronjob:
            self.create_cron()
        else:
            self.remove_cron()
        self.restart_nginx()

    @on('done', 'click')
    def on_output_done(self):
        self.find('hidden_output').visible = False
        
    @on('tabs', 'switch')
    def tab_switched(self):
        self.refresh()
        
    @on('save', 'click')
    def save_button(self):
        self.save()       

    @on('updatenginx', 'click')
    def updatenginx_button(self):     
        self.update_nginx_confs()
        self.restart_nginx()
    
    @on('helperbutton', 'click')
    def helper_button(self):
        self.helper()

    @on('request', 'click')
    def request_button(self):
        self.settings.output = "Saving configuration... Waiting 5 seconds..."
        self.binder.setup(self.settings).populate()
        self.find('hidden_output').visible = True
        self.start_thread(self.request_certs_helper)
      