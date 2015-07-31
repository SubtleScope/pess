<!--
     #################################
     # Phonehome PHP Script (snort.php)
     #
     # Written By: M4dH4tt3r
     #     
     # For use with daily_backup.sh
     #################################
-->

<html>
 <head>
  <title>
    Token Management
  </title>
 </head>
 <body>
   <?php
     $target = $_SERVER['REMOTE_ADDR'];
     $plainStr = 'xXxGen<Owned By G0dz1ll4>GenxXx';
     $obfsStr = str_replace('\n', '', base64_encode($plainStr));
     $userAgent = $_SERVER['HTTP_USER_AGENT'];

     if (isset($_POST['token'])) {
        if (str_replace('\n', '', $_POST['token']) == $obfsStr && $userAgent == "H4x0r Lit3 - Ph0n3H0m3 v1.0") {
           echo "Phonehome successful from $target at " . date(DATE_RFC2822) . "!";
        }
     }
   ?>

 </body>
</html>
