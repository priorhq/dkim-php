<?php
/**
 * DKIMconfig class
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */

namespace Prior\DkimPhp;

/**
 * Step by Step guide to generate your encryption keys and populate them through your DNS records.
 *
 * ### Make your own copy of config file
 *
 * Before starting you should make a copy of folder `config/` and store it outside your `vendor/` Composer repository in
 * a non-public area of your website e.g.: ``` /www/inc/config/jv-conseil/dkim-php-mail-signature/ ```
 *
 * Failing to do so will expose you to lose all your settings in case of a future Composer udpate.
 *
 * ### Generate your Public & Private Encryption keys
 *
 * In Terminal enter this command line to start working under the path of your `config/` folder:
 * ```
 * cd /www/inc/config/jv-conseil/dkim-php-mail-signature/
 * ```
 *
 * In Terminal enter this command line to generate a new **private 2048 bit encryption key**:
 * ```
 * openssl genrsa -des3 -out private.pem 2048
 * ```
 *
 * Enter your **Pass Phrase** and save it for editing your `config.inc.php` file in the next step.
 *
 * Then retrieve your **public key**:
 * ```
 * openssl rsa -in private.pem -out public.pem -outform PEM -pubout
 * ```
 *
 * _You can delete the two originals `*.pem` file keys stored in the `config/` folder if they create a conflict in the
 * creation process of your keys._
 *
 * ### Edit your DNS with a new DKIM record
 *
 * Access your registrar interface (e.g.: OVH.com) and create a new **DKIM record**:
 * ```
 * selector._domainkey  IN TXT  ( "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ekggNf9vuzzL4SlVc8QZyyqbEwR5bVTPC9cEZ8hFqTKOc7go180n3RZilYJZvveaxBkLCVJSTQaMPtKuSptY5au6Pi3AkFlizzhUJ80+0zgZXSGx7gfbginbRwhD+XdGOe9NXpo0PfrD6dEJ49Ytx4/nHB0TKiL227C0kGWb7RfWTVWccgJq4+kQb4l+4" "oDU5rGomSYK+zmMV13QTSETcJnoXhmjoJ30omyJfEXAsK5Ny0LJo8rWCucLD31BxHrM9/+M/Ye+TWxcrD2mRh5Jxqcnyj00/7kCnWeGPTftVKkAJBP3JMRqCNShLUchLhaz0qeXUtxAe9dx7ltr8042QIDAQAB;" )
 * ```
 *
 * DKIM works better with **SPF** and **DMARC** records, you should consider editing them too:
 * ```
 * 3600     IN TXT  "v=spf1 include:_spf.google.com ~all"
 * _dmarc   IN TXT  "v=DMARC1; p=quarantine; rua=mailto:me@yourdomain.name"
 * ```
 *
 * Further reading:
 * - [Add DKIM domain key to domain DNS records](https://support.google.com/a/answer/173535)
 * - [Manage suspicious emails with DMARC](https://support.google.com/a/answer/2466563?hl=en)
 * - [Help prevent email spoofing with SPF records](https://support.google.com/a/answer/33786?hl=en)
 *
 * ### Edit your Config File
 *
 * Under `config/config.sample.inc.php` you will find a config file example to help you set your own details.
 *
 * Now you can drop `.sample` in the filename and start editing it:
 * - **domain**: your domain name e.g: google.com
 * - **selector**: <selector> used in your DKIM DNS record, e.g.: selector._domainkey.MAIL_DKIM_DOMAIN
 * - **passphrase**: your pass phrase used to generate your keys e.g.: myPassPhrase.
 * - ... other parameters can be omitted.
 *
 * ### Usage
 *
 * Sample lines to import into your mail code to start signing with DKIM:
 * ```
 * require_once __DIR__ . '/../vendor/autoload.php' ; // Autoload files using Composer autoload
 * use JVconseil\DkimPhpMailSignature\DKIMsign ;
 * use JVconseil\DkimPhpMailSignature\DKIMconfig ;
 *
 * // init
 * $config = new DKIMconfig('/www/inc/config/jv-conseil/dkim-php-mail-signature/config.inc.php') ;
 *
 * // set: this calls __set()
 * $config->domain = "mynewdomain.name" ;
 *
 * // get: this calls __get()
 * $config->domain ; // => "mynewdomain.name" ;
 * ```
 *
 * @example /../config/config.sample.inc.php Here is config.sample.inc.php:
 *
 * @return string Configuration paramaters to sign your email with DKIM.
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */
class DkimConfig
{

    /**
     * @var string $configFile store the path to your <config/config.inc.php> file
     */
    protected $configFile = null;

    /**
     * @return array an array of configuration paramaters stored in $configFile
     */
    private function includeConfigFile($configFile = null)
    {
        if (!$configFile)
        {
            $configFile = __DIR__ . '/../config/config.sample.inc.php';
        }

        if (file_exists($configFile))
        {
            return include_once($configFile) ;
        }
        else
        {
            die('Config file does not exists: ' . $configFile) ;
        }
    }

    /**
     * @var array $data populated by an array of items stored in $configFile
     */
    private $data;

    /** @return object populated items to DKIMconfig class */
    public function __construct($configFile)
    {
        $this->data = $this->includeConfigFile($configFile) ;
    }

    /**
     * @return string magic methods!
     */
    public function __set($property, $value)
    {
        return $this->data[$property] = $value;
    }

    /** @return string the property value */
    public function __get($property)
    {
        return array_key_exists($property, $this->data) ?
            $this->data[$property] :
            null;
    }
}
