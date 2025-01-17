<?php
/**
 * DKIMmail class
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */

namespace JVconseil\DkimPhpMailSignature ;

/**
 * DKIMmail class
 *
 * ### Usage
 * ```
 * // init
 * $mail = new DKIMmail('/www/inc/config/jv-conseil/dkim-php-mail-signature/config.inc.php') ;
 *
 * // parameters
 * $mail->from    = "Sender" <sender@yourdomain.com> ;
 * $mail->to      = "Recipient" <recipient@yourdomain.com> ;
 * $mail->subject = "Your Mail Subject" ;
 * $mail->body    = "Your Mail Message." ;
 * $mail->attach("/path/to/your/attachment.jpg", "NameOfYourAttachment.jpg") ;
 *
 * // send!
 * $mail->send() ;
 * ```
 *
 * ### Sponsorship
 *
 * If this project helps you reduce time to develop, you can give me a cup of coffee ☕️ :-)
 *
 * [![Donate with PayPal](https://www.paypalobjects.com/en_US/FR/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=P3DGL6EANDY96&source=url)
 *
 * @example /../examples/SendMail.php Send DKIM sign emails:
 *
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @see https://github.com/JV-conseil-Internet-Consulting/dkim-php-mail-signature
 * @see https://packagist.org/packages/jv-conseil/dkim-php-mail-signature
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.2
 */
class DkimMail
{

    /**
     * @var string $_config_file store the path to your <config/config.inc.php> file
     */
    protected $_config_file = null ;

    public $to = null ;
    public $from = null ;
    public $headers = null ;
    public $subject = null ;
    public $body = null ;
    public $is_html = true ;
    public $return_receipt = false ;
    public $parts = array() ;

    public function __construct($_config_file)
    {
        $this->config = new DKIMconfig($_config_file) ;
    }

    public function attach($message, $name, $ctype = '')
    {

        if (!$ctype)
        {
            $ctype = mime_content_type($message);
        }

        $encode = 'base64';
        if (in_array($ctype, ['text/plain','text/html']))
        {
            $encode = '7bit';
        }

        $this->parts[] = array(
            'ctype'     => $ctype,
            'message' => $message,
            'encode'    => $encode,
            'name'          => $name
        );
    }

    // fonction utilisee pour contruire le message MIME
    // utilisee depuis build_multipart()
    private function buildMessage($part, $charset = 'UTF-8')
    {
        $message = $part['message'];
        $encoding = $part['encode'];
        $filename = $part['name'];
        $mime = "\r\nContent-Transfer-Encoding: $encoding";
        $mime.= "\r\nContent-Type: $part[ctype]; ";
        if ($filename) {
            $mime.= "x-unix-mode=0644; name=$filename";
            $mime.= "\r\nContent-Disposition:attachment; filename=$filename";
            $mime.= "\r\nContent-Description: $filename";
        } else {
            $mime.= "charset=$charset";
            $mime.= "\r\nContent-Disposition: inline";
        }
        // Error: dkim=neutral (body hash did not verify)
        // src: https://stackoverflow.com/questions/40433050/dkim-only-works-on-short-messages
        // DKIM may break if line length is too long :
        // Each line of characters SHOULD be no more than 78 characters, excluding the CRLF
        // if ($encoding == 'base64') $message = chunk_split(base64_encode($message)) ;
        // if ($encoding == 'base64') $message = chunk_split(base64_encode($message), 64, PHP_EOL) ;
        if ($encoding == 'base64') $message = chunk_split(base64_encode($message), 78, "\r\n") ;
        return  $mime . "\r\n" . $message ;
    }

    // compose le message MIME
    // utilisee depuis send()
    function build_multipart($type='mixed', $charset='UTF-8', $boundary='') {
        if (!$boundary) $boundary = "DKIMmail-Part-".md5(uniqid(time())) ;
        // $multipart = "Content-Type: multipart/$type;boundary=$boundary\r\n--$boundary";
        $multipart = "\r\n--$boundary" ;
        for($i = sizeof($this->parts) - 1; $i >= 0; $i--) {
            $multipart.= $this->buildMessage($this->parts[$i],$charset) . "\r\n--$boundary" ;
        }
        return $multipart.=  "--\r\n" ;
    }

    /**
     * Send the mail
     * @param string $test = true : do not send the email but displays the command
     */
    function send($test=false) {
        $mime = '' ;
        $charset = 'UTF-8' ;
        if (!empty($this->from)) $mime.= "From: ".$this->from."\r\n" ;
        if (!empty($this->headers)) $mime.= $this->headers."\r\n" ;
        $mime.= "Date: " . date("r") . "\r\n" ;
        $mime.= "X-Mailer: PHP/" . phpversion() . "\r\n" ; // entetes supplementaires (optionnel)
        $mime.= "X-Sender: <www." . $this->config->domain . ">\r\n" ;

        if ($this->return_receipt) {
            $mime.= "X-auth-smtp-user: " . ($x = preg_replace('/^(.*)<(.*)>/i', '\2', $this->from)) . "\r\n" ;
            $mime.= "X-abuse-contact: " . $x . "\r\n" ;
            $mime.= "X-Priority: 1\r\n" ;
            $mime.= "Disposition-Notification-To: " . $x . "\r\n" ;
            $mime.= "Return-receipt-to: " . $x . "\r\n" ;
            $mime.= "X-Confirm-Reading-To: " . $x . "\r\n" ;
        }

        $mime.= "Thread-Topic: " . $this->subject . "\r\n" ;
        $mime.= "MIME-Version: 1.0 \r\n" ;

        $text_type = "text/plain" ;
        if ($this->is_html) $text_type = "text/html" ;

        $boundary = "DKIMmail-Part-" . md5(uniqid(time())) ;
        $mime.= "Content-Type: multipart/mixed; boundary=\"$boundary\"" ;
        if (!empty($this->body)) $this->attach($this->body, null, $text_type) ;
        $body = $this->build_multipart('mixed', $charset, $boundary) ;

        /* Cas des mails avec PJ
           if (count($this->parts) > 0) {
           if (!empty($this->body)) $this->attach($this->body, "", $text_type) ;
           $boundary = "DKIMmail-Part-" . md5(uniqid(time())) ;
           $mime.= "Content-Type: multipart/mixed; boundary=\"$boundary\"";
           // $mime = $this->build_multipart('mixed', $charset, $boundary) ;
           // $body = null ;
           $body = $this->build_multipart('mixed', $charset, $boundary) ;
           } else { // Cas des mails tous simples
           $mime.= "Content-Type: $text_type; charset=$charset \r\n";
           $mime.= "Content-Transfer-Encoding: 7bit \r\n";
           $mime.= "Content-Disposition: inline \r\n";
           $body = $this->body ;
           }
        */

        /* Make sure linefeeds are in CRLF format - it is essential for signing **/
        $this->body = preg_replace('/(?<!\r)\r\n/', "\r\n", $body) ;
        $this->headers = preg_replace('/(?<!\r)\r\n/', "\r\n", $mime) ;

        $sign = new DKIMsign(
            $this->config->private_key,
            $this->config->passphrase,
            $this->config->domain,
            $this->config->selector
        );

        $this->signed_headers = $sign->get_signed_headers($this->to, $this->subject, $this->body, $this->headers) ;

        // envoi du message
        if ($test == false) {

            $additional_parameters = null ;
            return mail($this->to, $this->subject, $this->body, $this->signed_headers.$this->headers, $additional_parameters) ;

        } else {

            echo nl2br(htmlentities("
      ----------------
      TEST DU MESSAGE
      ----------------

      {$mime}TO: $this->to
      SUBJECT: $this->subject

      $body

      ---------------- FIN DU MESSAGE ----------------

      "));
            return false;
        }
    }

} ;
