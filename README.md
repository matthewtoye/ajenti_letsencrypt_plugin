# Ajenti LetsEncrypt Plugin

**BETA VERSION: USE WITH CAUTION. TESTED ON UBUNTU 16.04**

Easily create Let's Encrypt signed certificates to secure your server

BEFORE installing this, make sure you have Nginx and Ajenti installed (This is a great guide: https://websiteforstudents.com/installing-ajenti-on-ubuntu-16-04-lts-server/)

## Installation
```
# Clone this repository to `<ajenti_source>/plugins` or `/var/lib/ajenti/plugins`
	-git clone https://github.com/matthewtoye/ajenti_letsencrypt_plugin.git /var/lib/ajenti/plugins/letsencrypt
	
# Restart Ajenti
	-service ajenti restart (debian)
	
# (optional) Run in debug mode
	-service ajenti stop
	-ajenti-panel -v
```

## Usage

* In Ajenti-Panel go to `Security -> LetsEncrypt`
* Replace your config options depending on your os (Dehydrated Basedir, Dehydrated Filename, Wellknown Basedir should all be preset and will work fine on Ubuntu 16.04)
* Fill in the domains you want to create certificates for
  * Add a new domain, without any sub-domain (ex: mydomain.com)
  * Expand the domain, and add your sub-domains (1 per line, ie: www.mydomain.com)
* Click `Save` to store your settings but prevent requesting certificates
* Click `Request` to request your certificates
  * Check `Force Renewal` to request certs no matter what
* Set the SSL-certificates per domain in your `Websites` tabs OR click use Certs to automatically match Nginx files with available certificates and configure files (THIS IS BETA)