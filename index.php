<form method="GET">
  <input type="text" name="input" />
  <input type="submit" name="start" value="send" />
</form>

<?php
/* Enable Firewall */
define('PHP_FIREWALL_STATUS', true);
include("security.php");

$x = $_GET['input'];
echo $x;
?>
