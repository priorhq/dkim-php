# DkimPhpMailSignature

[![Packagist Version](https://img.shields.io/packagist/v/jv-conseil/dkim-php-mail-signature?color=orange)](https://packagist.org/packages/jv-conseil/dkim-php-mail-signature)
[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=P3DGL6EANDY96&source=url)
[![License BSD 3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)
[![Follow JV conseil – Internet Consulting on Twitter](https://img.shields.io/twitter/follow/JVconseil.svg?style=social&logo=twitter)](https://twitter.com/JVconseil)

> 📬 Stand-alone DKIM class to sign your emails with a 2048 bit private key hashed with SHA-256 algorithm.

![DkimPhpMailSignature](https://user-images.githubusercontent.com/8126807/69017623-83495b80-09a8-11ea-8eee-757594d4e6ab.png)

# Usage

Sample lines to import into your mail code to start signing with DKIM:
```
require_once __DIR__ . '/../vendor/autoload.php' ; // Autoload files using Composer autoload
use JVconseil\DkimPhpMailSignature\DKIMsign ;
use JVconseil\DkimPhpMailSignature\DKIMconfig ;

// init
$config = new DKIMconfig('/www/inc/config/jv-conseil/dkim-php-mail-signature/config.inc.php') ;
$sign = new DKIMsign(
	$config->private_key,
	$config->passphrase,
	$config->domain,
	$config->selector
) ;

// sign
$signed_headers = $sign->get_signed_headers($to, $subject, $message, $headers) ;

// send email
mail($to, $subject, $message, $signed_headers.$headers) ;
```

# Installation
> Step by Step guide to generate your encryption keys and populate them through your DNS records.

## Installation & loading

DkimPhpMailSignature is available on [Packagist](https://packagist.org/packages/jv-conseil/dkim-php-mail-signature) (using semantic versioning), and installation via [Composer](https://getcomposer.org) is the recommended way to install DkimPhpMailSignature. Just add this line to your `composer.json` file:

```json
"jv-conseil/dkim-php-mail-signature": "^1.0"
```

or run

```sh
composer require jv-conseil/dkim-php-mail-signature
```

Note that the `vendor` folder and the `vendor/autoload.php` script are generated by Composer; they are not part of DkimPhpMailSignature.

## Make your own copy of config file

Before starting you should make a copy of folder `config/` and store it outside your `vendor/` Composer repository in a non-public area of your website e.g.: 
```
/www/inc/config/jv-conseil/dkim-php-mail-signature/
```

Failing to do so will expose you to lose all your settings in case of a future Composer udpate.

## Generate your Public & Private Encryption keys

In Terminal enter this command line to start working under the path of your `config/` folder:
```
cd /www/inc/config/jv-conseil/dkim-php-mail-signature/
```

In Terminal enter this command line to generate a new **private 2048 bit encryption key**:
```
openssl genrsa -des3 -out private.pem 2048
```

Enter your **Pass Phrase*and save it for editing your `config.inc.php` file in the next step.

Then retrieve your **public key**:
```
openssl rsa -in private.pem -out public.pem -outform PEM -pubout
```

_You can delete the two originals `*.pem` file keys stored in the `config/` folder if they create a conflict in the creation process of your keys._

## Edit your DNS with a new DKIM record

Access your registrar interface (e.g.: OVH.com) and create a new **DKIM record** to declare your **public key**:
```
selector._domainkey  IN TXT  ( "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ekggNf9vuzzL4SlVc8QZyyqbEwR5bVTPC9cEZ8hFqTKOc7go180n3RZilYJZvveaxBkLCVJSTQaMPtKuSptY5au6Pi3AkFlizzhUJ80+0zgZXSGx7gfbginbRwhD+XdGOe9NXpo0PfrD6dEJ49Ytx4/nHB0TKiL227C0kGWb7RfWTVWccgJq4+kQb4l+4" "oDU5rGomSYK+zmMV13QTSETcJnoXhmjoJ30omyJfEXAsK5Ny0LJo8rWCucLD31BxHrM9/+M/Ye+TWxcrD2mRh5Jxqcnyj00/7kCnWeGPTftVKkAJBP3JMRqCNShLUchLhaz0qeXUtxAe9dx7ltr8042QIDAQAB;" )
```

DKIM works better with **SPF** and **DMARC** records, you should consider editing them too:
```
3600     IN TXT  "v=spf1 include:_spf.google.com ~all"
_dmarc   IN TXT  "v=DMARC1; p=quarantine; rua=mailto:me@yourdomain.name"
```

Further reading:
- [Add DKIM domain key to domain DNS records](https://support.google.com/a/answer/173535)
- [Manage suspicious emails with DMARC](https://support.google.com/a/answer/2466563?hl=en)
- [Help prevent email spoofing with SPF records](https://support.google.com/a/answer/33786?hl=en)

## Edit your Config File

Under `config/config.sample.inc.php` you will find a config file example to help you set your own details.

Now you can drop `.sample` in the filename and start editing it:
- **domain**: your domain name e.g: google.com
- **selector**: <selector> used in your DKIM DNS record, e.g.: selector._domainkey.MAIL_DKIM_DOMAIN
- **passphrase**: your pass phrase used to generate your keys e.g.: myPassPhrase.
- ... other parameters can be omitted.

## Usage

Sample lines to import into your mail code to start signing with DKIM:
```
require_once __DIR__ . '/../vendor/autoload.php' ; // Autoload files using Composer autoload
use JVconseil\DkimPhpMailSignature\DKIMsign ;
use JVconseil\DkimPhpMailSignature\DKIMconfig ;

// init
$config = new DKIMconfig('/www/inc/config/jv-conseil/dkim-php-mail-signature/config.inc.php') ;

// set: this calls __set()
$config->domain = "mynewdomain.name" ;

// get: this calls __get()
$config->domain ; // => "mynewdomain.name" ;
```

# Introducing DKIMmail class

> 📬 Stand-alone class to send DKIM signed emails with a 2048 bit private key hashed with SHA-256 algorithm.

```
// init
$mail = new DKIMmail('/www/inc/config/jv-conseil/dkim-php-mail-signature/config.inc.php') ;

// parameters
$mail->from    = "Sender" <sender@yourdomain.com> ;
$mail->to      = "Recipient" <recipient@yourdomain.com> ;
$mail->subject = "Your Mail Subject" ;
$mail->body    = "Your Mail Message." ;
$mail->attach("/path/to/your/attachment.jpg", "NameOfYourAttachment.jpg") ;

// send!
$mail->send() ;
```

# Documentation 

Documentation is [available online](https://jv-conseil-internet-consulting.github.io/dkim-php-mail-signature/classes/JVconseil.DkimPhpMailSignature.DKIMconfig.html), though it may not be quite up to date or match your version exactly.

You can generate API documentation by running `phpdoc` in the top-level folder of this project, and documentation will be generated in this folder:
```
php ~/vendor/bin/phpdoc -d ~/dkim-php-mail-signature/ -t ~/dkim-php-mail-signature/docs/
```

You will need to have [phpDocumentor](https://www.phpdoc.org) installed.


# Sponsorship

If this project helps you reduce time to develop, you can give me a cup of coffee ☕️ :-)

[![Donate with PayPal](https://www.paypalobjects.com/en_US/FR/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=P3DGL6EANDY96&source=url)