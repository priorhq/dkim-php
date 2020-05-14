<?php
/**
 * Stand-alone DKIM class to sign email with a 2048 bit private key hashed with SHA-256 algorithm. This stand-alone
 * DKIM class is based on the work made by Louis Ameline and PHP-MAILER (see license below).
 *
 * **The differences are :**
 * - algorithm to hash DKIM key is SHA-256
 * - 2048 bit key encryption
 * - composer distributed
 * - ...
 *
 * If the class fails to sign the e-mail, the returned DKIM header will be empty and the mail
 * will still be sent, just unsigned. A php warning is thrown for logging.
 *
 * *NOTE: you will NOT be able to use Domain Keys with PHP's mail() function, since it does
 * not allow to prepend the DK header before the To and Subject ones. DKIM is ok with that,
 * but Domain Keys is not. If you still want Domain Keys, you will have to manage to send
 * your mail straight to your MTA without the mail() function.*
 *
 * ### php-mail-signature by Louis Ameline
 *
 * https://github.com/louisameline/php-mail-signature
 *
 * Author: Louis Ameline - 04/2012
 *
 *
 * This stand-alone DKIM class is based on the work made on PHP-MAILER (see license below).
 * The differences are :
 * - it is a standalone class
 * - it supports Domain Keys header
 * - it supports UTF-8
 * - it will let you choose the headers you want to base the signature on
 * - it will let you choose between simple and relaxed body canonicalization
 *
 * If the class fails to sign the e-mail, the returned DKIM header will be empty and the mail
 * will still be sent, just unsigned. A php warning is thrown for logging.
 *
 * NOTE: you will NOT be able to use Domain Keys with PHP's mail() function, since it does
 * not allow to prepend the DK header before the To and Subject ones. DKIM is ok with that,
 * but Domain Keys is not. If you still want Domain Keys, you will have to manage to send
 * your mail straight to your MTA without the mail() function.
 *
 * Successfully tested against Gmail, Yahoo Mail, Live.com, appmaildev.com
 * Hope it helps and saves you plenty of time. Let me know if you find issues.
 *
 * For more info, you should read :
 * - http://www.ietf.org/rfc/rfc4871.txt
 * - http://www.zytrax.com/books/dns/ch9/dkim.html
 *
 *
 * ### Original PHPMailer CC info :
 *
 * ```
 * .---------------------------------------------------------------------------.
 * |  Software: PHPMailer - PHP email class                                    |
 * |   Version: 5.2.1                                                          |
 * |      Site: https://code.google.com/a/apache-extras.org/p/phpmailer/       |
 * | ------------------------------------------------------------------------- |
 * |     Admin: Jim Jagielski (project admininistrator)                        |
 * |   Authors: Andy Prevost (codeworxtech) codeworxtech@users.sourceforge.net |
 * |          : Marcus Bointon (coolbru) coolbru@users.sourceforge.net         |
 * |          : Jim Jagielski (jimjag) jimjag@gmail.com                        |
 * |   Founder: Brent R. Matzelle (original founder)                           |
 * | Copyright (c) 2010-2012, Jim Jagielski. All Rights Reserved.              |
 * | Copyright (c) 2004-2009, Andy Prevost. All Rights Reserved.               |
 * | Copyright (c) 2001-2003, Brent R. Matzelle                                |
 * | ------------------------------------------------------------------------- |
 * |   License: Distributed under the Lesser General Public License (LGPL)     |
 * |            http://www.gnu.org/copyleft/lesser.html                        |
 * | This program is distributed in the hope that it will be useful - WITHOUT  |
 * | ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or     |
 * | FITNESS FOR A PARTICULAR PURPOSE.                                         |
 * '---------------------------------------------------------------------------'
 * ```
 *
 * ### PHPdocumentor
 *
 * Edit your documentation with this command line:
 * ```
 * php ~/vendor/bin/phpdoc -d ~/dkim-php-mail-signature/ -t ~/Documents/GitHub/dkim-php-mail-signature/docs/
 * ```
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */

namespace Prior\Dkim;

/**
 * Stand-alone DKIM class to sign email with a 2048 bit private key hashed with SHA-256 algorithm.
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
 * $sign = new DKIMsign(
 * $config->privateKey,
 * $config->passphrase,
 * $config->domain,
 * $config->selector) ;
 *
 * // sign
 * $signed_headers = $sign->getSignedHeaders($to, $subject, $message, $headers) ;
 *
 * // send email
 * mail($to, $subject, $message, $signed_headers.$headers) ;
 * ```
 *
 * ### Test Examples in Terminal
 *
 * In Terminal enter this command line to start testing examples:
 * ```
 * php ~/dkim-php-mail-signature/examples/SignSimple.php
 * ```
 *
 * @example /../examples/SignSimple.php Simple example with config file accessed through a var:
 * @example /../examples/SignWithConfigClass.php Class example with config file accessed through a class:
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */
class DkimSign
{

    /**
     * @var string $privateKey Provide your 2048 bit private key generated in Terminal with command line: ```openssl
     * genrsa -des3 -out private.pem 2048```
     */
    private $privateKey;

    /**
     * @var string $domain is your domain name e.g.: google.com
     */
    private $domain;

    /**
     * @var string $selector is your selector DNS DKIM record e.g.: selector._domainkey.google.com.
     */
    private $selector;

    /**
     * @var array $options
     */
    private $options;
    private $canonicalizedHeadersRelaxed;

    public function __construct($privateKey, $passphrase, $domain, $selector, $options = [])
    {
        // prepare the resource
        $this->privateKey = openssl_get_privatekey($privateKey, $passphrase);
        $this->domain = $domain;
        $this->selector = $selector;

        /**
         * This function will not let you ask for the simple header canonicalization because
         * it would require more code, it would not be more secure and mails would yet be
         * more likely to be rejected : no point in that
         */
        $defaultOptions = [
            'use_dkim' => true,
            /**
             * Specify whether to sign with SHA-256 (recommended) or the older, weaker SHA-1.
             * This variable takes either the value "sha1" or "sha256", as those are the only
             * two algorithms supported by the current version of DKIM.
             */
            'dkim_hash' => 'sha256',
            // disabled by default, see why at the top of this file
            'use_domainKeys' => false,
            /**
             * Allowed user, defaults is "@<MAIL_DKIM_DOMAIN>", meaning anybody in the
             * MAIL_DKIM_DOMAIN domain. Ex: 'admin@mydomain.tld'. You'll never have to use
             * this unless you do not control the "From" value in the e-mails you send.
             */
            'identity' => null,
            // "relaxed" is recommended over "simple" for better chances of success
            'dkim_body_canonicalization' => 'relaxed',
            // "nofws" is recommended over "simple" for better chances of success
            'dk_canonicalization' => 'nofws',
            /**
             * The default list of headers types you want to base the signature on. The
             * types here (in the default options) are to be put in lower case, but the
             * types in $options can have capital letters. If one or more of the headers
             * specified are not found in the $headers given to the function, they will
             * just not be used.
             * If you supply a new list, it will replace the default one
             */
            'signed_headers' => [
                'mime-version',
                'from',
                'to',
                'subject',
                'reply-to'
            ],
        ];

        if (isset($options['signed_headers']))
        {
            // lower case fields
            foreach ($options['signed_headers'] as $key => $value)
            {
                $options['signed_headers'][$key] = strtolower($value);
            }

            // delete the default fields if a custom list is provided, not merge
            $defaultOptions['signed_headers'] = [];
        }

        $this->options = array_replace_recursive($defaultOptions, $options);
    }

    /**
     * This function returns an array of relaxed canonicalized headers (lowercases the
     * header type and cleans the new lines/spaces according to the RFC requirements).
     * only headers required for signature (specified by $options) will be returned
     * the result is an array of the type : [headerType => fullHeader [, ...]),
     * e.g. ['mime-version' => 'mime-version:1.0')
     */
    private function dkimCanonicalizeHeadersRelaxed($headersString)
    {
        $headers = [];

        // a header value which is spread over several lines must be 1-lined
        $headersString = preg_replace("/\n\s+/", ' ', $headersString);

        $lines = explode("\r\n", $headersString);

        foreach ($lines as $key => $line)
        {
            // delete multiple WSP
            $line = preg_replace("/\s+/", ' ', $line);

            if (!empty($line))
            {
                // header type to lowercase and delete WSP which are not part of the
                // header value
                $line = explode(':', $line, 2);

                $headerType = trim(strtolower($line[0]));
                $headerValue = trim($line[1]);

                if (in_array($headerType, $this->options['signed_headers']) || $headerType == 'dkim-signature')
                {
                    $headers[$headerType] = $headerType . ':' . $headerValue;
                }
            }
        }

        return $headers;
    }

    /**
     * Apply RFC 4871 requirements before body signature. Do not modify
     */
    private function dkimCanonicalizeBodySimple($body)
    {
        /**
         * Unlike other libraries, we do not convert all \n in the body to \r\n here
         * because the RFC does not specify to do it here. However it should be done
         * anyway since MTA may modify them and we recommend you do this on the mail
         * body before calling this DKIM class - or signature could fail.
         */

        // remove multiple trailing CRLF
        while (mb_substr($body, mb_strlen($body, 'UTF-8') - 4, 4, 'UTF-8') == "\r\n\r\n")
        {
            $body = mb_substr($body, 0, mb_strlen($body, 'UTF-8') - 2, 'UTF-8');
        }

        // must end with CRLF anyway
        if (mb_substr($body, mb_strlen($body, 'UTF-8') - 2, 2, 'UTF-8') != "\r\n")
        {
            $body .= "\r\n";
        }

        return $body;
    }

    /**
     * Apply RFC 4871 requirements before body signature. Do not modify
     */
    private function dkimCanonicalizeBodyRelaxed($body)
    {
        $lines = explode("\r\n", $body);

        foreach ($lines as $key => $value)
        {
            // ignore WSP at the end of lines
            $value = rtrim($value);

            // ignore multiple WSP inside the line
            $lines[$key] = preg_replace('/\s+/', ' ', $value);
        }

        $body = implode("\r\n", $lines);

        // ignore empty lines at the end
        $body = $this->dkimCanonicalizeBodySimple($body);

        return $body;
    }

    /**
     * Apply RFC 4870 requirements before body signature. Do not modify
     */
    private function dkCanonicalizeSimple($body, $headersString)
    {
        /**
         * Note : the RFC assumes all lines end with CRLF, and we assume you already
         * took care of that before calling the class
         */

        // keep only headers which are in the signature headers
        $headers = explode("\r\n", $headersString);
        foreach ($headers as $key => $line)
        {
            if (!empty($headers))
            {
                // make sure this line is the line of a new header and not the
                // continuation of another one
                $c = substr($line, 0, 1);
                $isSignedHeader = true;

                // new header
                if (!in_array($c, ["\r", "\n", "\t", ' ']))
                {
                    $h = explode(':', $line);
                    $headerType = strtolower(trim($h[0]));

                    // keep only signature headers
                    if (in_array($headerType, $this->options['signed_headers']))
                    {
                        $isSignedHeader = true;
                    }
                    else
                    {
                        unset($headers[$key]);
                        $isSignedHeader = false;
                    }
                }
                // continuated header
                else
                {
                    // do not keep if it belongs to an unwanted header
                    if ($isSignedHeader == false)
                    {
                        unset($headers[$key]);
                    }
                }
            }
            else
            {
                unset($headers[$key]);
            }
        }
        $headersString = implode("\r\n", $headers);

        $mail = $headersString . "\r\n\r\n" . $body . "\r\n";

        // remove all trailing CRLF
        while (mb_substr($body, mb_strlen($mail, 'UTF-8') - 4, 4, 'UTF-8') == "\r\n\r\n")
        {
            $mail = mb_substr($mail, 0, mb_strlen($mail, 'UTF-8') - 2, 'UTF-8');
        }

        return $mail;
    }

    /**
     * Apply RFC 4870 requirements before body signature. Do not modify
     */
    private function dkCanonicalizeNofws($body, $headersString)
    {
        // HEADERS
        // a header value which is spread over several lines must be 1-lined
        $headersString = preg_replace("/\r\n\s+/", ' ', $headersString);

        $headers = explode("\r\n", $headersString);

        foreach ($headers as $key => $line)
        {
            if (!empty($line))
            {
                $h = explode(':', $line);
                $headerType = strtolower(trim($h[0]));

                // keep only signature headers
                if (in_array($headerType, $this->options['signed_headers']))
                {
                    // delete all WSP in each line
                    $headers[$key] = preg_replace("/\s/", '', $line);
                }
                else
                {
                    unset($headers[$key]);
                }
            }
            else
            {
                unset($headers[$key]);
            }
        }
        $headersString = implode("\r\n", $headers);

        // BODY
        // delete all WSP in each body line
        $bodyLines = explode("\r\n", $body);

        foreach ($bodyLines as $key => $line)
        {
            $bodyLines[$key] = preg_replace("/\s/", '', $line);
        }

        $body = rtrim(implode("\r\n", $bodyLines)) . "\r\n";

        return $headersString . "\r\n\r\n" . $body;
    }

    /**
     * The function will return no DKIM header (no signature) if there is a failure,
     * so the mail will still be sent in the default unsigned way
     * it is highly recommended that all linefeeds in the $body and $headers you submit
     * are in the CRLF (\r\n) format !! Otherwise signature may fail with some MTAs
     */
    private function getDkimHeader($body)
    {
        $body = ($this->options['dkim_body_canonicalization'] == 'simple') ?
            $this->dkimCanonicalizeBodySimple($body) :
            $this->dkimCanonicalizeBodyRelaxed($body);

        // Base64 of packed binary hash of body
        debug($body);

        $bh = base64_encode(pack('H*', hash($this->options['dkim_hash'], $body)));
        debug($bh);

        $identityPart = ($this->options['identity'] == null) ? '' : ' i=' . $this->options['identity'] . ';' . "\r\n\t";

        $dkimHeader =
            'DKIM-Signature: ' .
            'v=1;' . "\r\n\t" .
            'a=rsa-' . $this->options['dkim_hash'] . ';'."\r\n\t" .
            'q=dns/txt;' . "\r\n\t" .
            's=' . $this->selector . ';'."\r\n\t" .
            't=' . time() . ';' . "\r\n\t" .
            'c=relaxed/' . $this->options['dkim_body_canonicalization'].';'."\r\n\t" .
            'h=' . implode(':', array_keys($this->canonicalizedHeadersRelaxed)).';'."\r\n\t" .
            'd=' . $this->domain . ';'."\r\n\t" .
            $identityPart .
            'bh='. $bh . ';'."\r\n\t" .
            'b=';

        // now for the signature we need the canonicalized version of the $dkimHeader
        // we've just made
        $canonicalizedDkimHeader = $this->dkimCanonicalizeHeadersRelaxed($dkimHeader);

        // we sign the canonicalized signature headers
        $toBeSigned = implode("\r\n", $this->canonicalizedHeadersRelaxed)
            . "\r\n" . $canonicalizedDkimHeader['dkim-signature'];

        // $signature is sent by reference in this function
        $signature = '';
        $signingAlgorithm = null;

        if ($this->options['dkim_hash'] === 'sha256')
        {
            $signingAlgorithm = OPENSSL_ALGO_SHA256;
        }
        else if ($this->options['dkim_hash'] === 'sha1')
        {
            $signingAlgorithm = OPENSSL_ALGO_SHA1;
        }
        else
        {
            die('Unsupported dkim_hash value "' . $this->options['dkim_hash'] . '" -- DKIM only supports sha256 and sha1.');
        }

        if (openssl_sign($toBeSigned, $signature, $this->privateKey, $signingAlgorithm))
        {
            $dkimHeader .= rtrim(chunk_split(base64_encode($signature), 64, "\r\n\t")) . "\r\n";
        }
        else
        {
            trigger_error(sprintf('Could not sign e-mail with DKIM : %s', $toBeSigned), E_USER_WARNING);
            $dkimHeader = '';
        }

        return $dkimHeader;
    }

    private function getDkHeader($body, $headersString)
    {
        // Creating DomainKey-Signature
        $domainkeysHeader =
            'DomainKey-Signature: ' .
            'a=rsa-' . $this->options['dkim_hash'] . ';' . "\r\n\t" .
            'c=' . $this->options['dk_canonicalization'].'; ' . "\r\n\t" .
            'd=' . $this->domain.'; ' . "\r\n\t" .
            's=' . $this->selector.'; ' . "\r\n\t" .
            'h=' . implode(':', array_keys($this->canonicalizedHeadersRelaxed)) . '; ' . "\r\n\t" .
            'b=';

        // we signed the canonicalized signature headers + the canonicalized body
        $toBeSigned = ($this->options['dk_canonicalization'] == 'simple') ?
            $this->dkCanonicalizeSimple($body, $headersString) :
            $this->dkCanonicalizeNofws($body, $headersString);

        $signature = '';
        $signingAlgorithm = null;

        if ($this->options['dkim_hash'] === 'sha256')
        {
            $signingAlgorithm = OPENSSL_ALGO_SHA256;
        }
        else if ($this->options['dkim_hash'] === 'sha1')
        {
            $signingAlgorithm = OPENSSL_ALGO_SHA1;
        }
        else
        {
            die('Unsupported dkim_hash value "' . $this->options['dkim_hash'] . '" -- DKIM only supports sha256 and sha1.');
        }

        if (openssl_sign($toBeSigned, $signature, $this->privateKey, $signingAlgorithm))
        {
            $domainkeysHeader .= rtrim(chunk_split(base64_encode($signature), 64, "\r\n\t")) . "\r\n";
        }
        else
        {
            trigger_error(sprintf('Could not sign e-mail with DKIM : %s', $toBeSigned), E_USER_WARNING);
            $domainkeysHeader = '';
        }

        return $domainkeysHeader;
    }

    /**
     * You may leave $to and $subject empty if the corresponding headers are already
     * in $headers
     */
    public function getSignedHeaders($to, $subject, $body, $headers)
    {
        $signedHeaders = '';

        if (!empty($to) || !empty($subject))
        {
            /**
             * To and Subject are not supposed to be present in $headers if you
             * use the php mail() function, because it takes care of that itself in
             * parameters for security reasons, so we reconstruct them here for the
             * signature only
             */
            $headers .= (mb_substr($headers, mb_strlen($headers, 'UTF-8') - 2, 2, 'UTF-8') == "\r\n") ? '' : "\r\n";

            if (!empty($to))
            {
                $headers .= 'To: ' . $to . "\r\n";
            }

            if (!empty($subject))
            {
                $headers .= 'Subject: ' . $subject . "\r\n";
            }
        }

        // get the clean version of headers used for signature
        $this->canonicalizedHeadersRelaxed = $this->dkimCanonicalizeHeadersRelaxed($headers);

        if (!empty($this->canonicalizedHeadersRelaxed))
        {
            // Domain Keys must be the first header, it is an RFC (stupid) requirement
            if ($this->options['use_domainKeys'] == true)
            {
                $signedHeaders .= $this->getDkHeader($body, $headers);
            }

            if ($this->options['use_dkim'] == true)
            {
                $signedHeaders .= $this->getDkimHeader($body);
            }
        }
        else
        {
            trigger_error('No headers found to sign the e-mail with !', E_USER_WARNING);
        }

        return $signedHeaders;
    }
}
