# Ajenti LetsEncrypt Plugin

**BETA VERSION: USE WITH CAUTION**

Easily create Let's Encrypt signed certificates to secure your server

## Requirements prior to installation
# Clone https://github.com/lukas2511/dehydrated into /etc/ (Full path after clone should be /etc/dehydrated)
	-git clone https://github.com/lukas2511/dehydrated /etc/dehydrated
# Install nginx
	-apt install nginx
	-service restart nginx
		
## Installation
```
# Clone this repository to `<ajenti_source>/plugins` or `/var/lib/ajenti/plugins`
	-git clone https://github.com/matthewtoye/ajenti_letsencrypt_plugin.git /var/lib/ajenti/plugins/letsencrypt
	
# Restart Ajenti
	-service ajenti restart (debian)
	
# Run in debug mode (optional)
	-service ajenti stop
	-ajenti-panel -v
```

## Usage

* In Ajenti-Panel go to `Security -> LetsEncrypt`
* Replace your config options depending on your os
* Dehydrated Basedir, Dehydrated Filename, Wellknown Basedir should all be preset and will work fine on Ubuntu
* Fill in the domains you want to create certificates for
  * 1 domain per row (e.g.: ROW 1: domain.com sub.domain.com blog.domain.com
							ROW 2: domain.net sub.domain.net	
							ROW 3: mydomain.org blog.mydomain.org)
* Click `Save` to store your settings but prevent requesting certificates
* Click `Request` to request your certificates
  * Check `Force Renewal` to request certs no matter what
* Set the SSL-certificates per domain in your `Websites` tabs