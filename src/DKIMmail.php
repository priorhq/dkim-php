<?php
/**
 * DKIMmail class
 * 
 * @author JV conseil — Internet Consulting <contact@jv-conseil.net>
 * @see http://www.jv-conseil.net
 * @license BSD 3-Clause License, Copyright (c) 2019, JV conseil – Internet Consulting, All rights reserved.
 * @version v1.2.0
 */

namespace JVconseil\DkimPhpMailSignature ;

/**
 * DKIMmail class
 * 
 * ### Usage
 * ```
 * // instanciation de la classe
 * $mail = new DKIMmail();
 * 
 * // parametres
 * $mail->to = "adresse@email";                // Adresse email de reception 
 * $mail->subject = "Test";                    // Sujet
 * $mail->body = "Ceci est un test.";          // Corps du message
 * $mail->from = "adresse@email";              // Adresse email de l'expediteur (optionnel)
 * $mail->headers = "Date: ";  // Entetes supplementaires (optionnel)
 * $mail->attach("$fichier", "test.jpg");      // fichier attache (optionnel)
 * 
 * // envoi du message
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
 * @version v1.2.0
 */
class DKIMmail {
  
  /** @var string $_config_file store the path to your <config/config.inc.php> file */
  protected $_config_file = null ;

  public $to = null ;
  public $from = null ;
  public $headers = null ;
  public $subject = null ;
  public $body = null ;
  public $is_html = false ;
  public $parts = array() ;

  /** constructeur */
  public function __construct($_config_file) {
    $this->config = new DKIMconfig($_config_file) ;
  }
  
  function set_html_format($html=true) {
    $this->is_html=$html;
  }


  // attache un fichier au message
  function attach($message,$name,$ctype='') {
    /*
    if(empty($ctype)) { // type de contenu non defini
      switch(strrchr(basename($name),".")) { // on essaie de reconnaitre l'extension
        case ".gz" :  $ctype =  "application/x-gzip"; break;
        case ".tgz":  $ctype =  "application/x-gzip"; break;
        case ".zip":  $ctype =  "application/zip";    break;
        case ".pdf":  $ctype =  "application/pdf";    break;        
        case ".png":  $ctype =  "image/png";  break;
        case ".gif":  $ctype =  "image/gif";  break;
        case ".jpg":  $ctype =  "image/jpeg"; break;
        case ".txt":  $ctype =  "text/plain"; break;
        case ".htm":  $ctype =  "text/html";  break;
        case ".html": $ctype =  "text/html";  break;
        case ".ics":  $ctype =  "text/calendar";  break;
        case ".doc":  $ctype =  "application/msword";  break;
        case ".xls":  $ctype =  "application/vnd.ms-excel";  break;
        default:      $ctype =  "application/octet-stream"; break;
      }
    }
    */
    if (!$ctype) $ctype = get_mime_type($name) ;
		
		$encode = 'base64';
    if (in_array($ctype, array('text/plain','text/html'))) $encode = '7bit';      

    $this->parts[] = array(
		'ctype' 	=> $ctype,
		'message' => $message,
		'encode' 	=> $encode,
		'name' 		=> $name
		);
  }

  // fonction utilisee pour contruire le message MIME
  // utilisee depuis build_multipart()
  function build_message($part, $charset='UTF-8') {
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
    if ($encoding == 'base64') $message = chunk_split(base64_encode($message), 76, PHP_EOL) ;
    return  $mime . "\r\n" . $message ;
  }

  // compose le message MIME
  // utilisee depuis send()
  function build_multipart($type='mixed', $charset='UTF-8', $boundary='') {
    if (!$boundary) $boundary = "DKIMmail-Part-".md5(uniqid(time())) ;
    // $multipart = "Content-Type: multipart/$type;boundary=$boundary\r\n--$boundary";
    $multipart = "\r\n--$boundary" ;
    for($i = sizeof($this->parts) - 1; $i >= 0; $i--) {
      $multipart.= $this->build_message($this->parts[$i],$charset)."\r\n--$boundary";
    }
    return $multipart.=  "--\r\n" ;
  }
  
  // envoie le message
  // derniere fonction a appeler . send(true) n'envoie pas le message mais affiche la commande
  function send($test=false) {
  	$mime = '' ;
  	$charset = 'UTF-8' ;
    if (!empty($this->from)) $mime.= "From: ".$this->from."\r\n" ;
    if (!empty($this->headers)) $mime.= $this->headers."\r\n" ;
		$mime.= "Date: ".gmdate("D, d M Y H:i:s", time())." -0000\r\n" ; // Correction de la date foireuse :
		$mime.= "X-Mailer: PHP/" . phpversion() . "\r\n" ; // entetes supplementaires (optionnel)
		$mime.= "X-Sender: <www." . $this->config->domain . ">\r\n" ; 
		$mime.= "X-auth-smtp-user: " . ($xabuse = preg_replace('/^(.*)<(.*)>/i', '\2', $this->from)) . "\r\n" ; 
    $mime.= "X-abuse-contact: " . $xabuse . "\r\n" ; 
    $mime.= "X-Priority: 1\r\n" ;
    $mime.= "Disposition-Notification-To: " . $xabuse . "\r\n" ;
    $mime.= "Return-receipt-to: " . $xabuse . "\r\n" ;
    $mime.= "X-Confirm-Reading-To: " . $xabuse . "\r\n" ;
    $mime.= "Thread-Topic: " . $this->subject . "\r\n" ;
    $mime.= "MIME-Version: 1.0 \r\n" ;
		
		if ($this->is_html) $text_type = "text/html"; else $text_type = "text/plain" ;
		
    // Cas des mails avec PJ
    if (count($this->parts) > 0) {
      if (!empty($this->body)) $this->attach($this->body, "", $text_type) ;
      /*
      $type = 'mixed';
      $body = "" ;
      $mime.= "MIME-Version: 1.0 \r\n" . $this->build_multipart('mixed', $charset) ;
      */
      $boundary = "DKIMmail-Part-" . md5(uniqid(time())) ;
      $mime.= "Content-Type: multipart/mixed; boundary=\"$boundary\"";
      $body = $this->build_multipart('mixed', $charset, $boundary) ;
    } else { // Cas des mails tous simples
			//$mime.= "MIME-Version: 1.0 \r\n";
			$mime.= "Content-Type: $text_type; charset=$charset \r\n";
			$mime.= "Content-Transfer-Encoding: 7bit \r\n";
			$mime.= "Content-Disposition: inline \r\n";
      $body = $this->body ;
    }

    /** Signature DKIM */
    /** Call Composer Package JVconseil\DkimPhpMailSignature */
    //require_once __DIR__ . '/../vendor/autoload.php' ; // Autoload files using Composer autoload

    //use JVconseil\DkimPhpMailSignature\DKIMsign ;
    //use JVconseil\DkimPhpMailSignature\DKIMconfig ;

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

		// mail($to, $subject, $message, $signed_headers.$headers) ;

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