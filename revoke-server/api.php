<?php
// The MIT License (MIT)
//
// Copyright (c) 2016 Marvin Böcker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// *** BEGIN CONFIGURE THIS ***

$dbhost = "localhost";
$dbuser = "root";
$dbpw = "";
$dbname = "edcert";
$dbtable = "revoked_certs";
$dbusemysqli = false;

// *** END CONFIGURE THIS ***

function is_revoked($public_key)
{
    global $dbhost, $dbuser, $dbpw, $dbname, $dbtable, $dbusemysqli;

    if ($dbusemysqli)
    {
        // open a database connection
        $mysqli = new mysqli($dbhost, $dbuser, $dbpw, $dbname);
        if ($mysqli->connect_errno)
        {
            // the connection may fail
            ?>{"err":"db conn failed"}<?php
            exit();
        }

        // request the status of the certificate
        $req = $mysqli->query("SELECT `revoke_id` FROM `$dbname`.`$dbtable` WHERE `public_key` = '$public_key' LIMIT 1");

        // has the certificate been revoked?
        $revoked = $req->num_rows > 0;

        // close the connection
        $mysqli->close();

        return $revoked;
    }
    else
    {
        $link = mysql_connect($dbhost, $dbuser, $dbpw, $dbname);

        if (!$link)
        {
            // the connection may fail
            ?>{"err":"db conn failed"}<?php
            exit();
        }


        mysql_select_db($dbtable);

        // request the status of the certificate
        $req = mysql_query("SELECT `revoke_id` FROM `$dbname`.`$dbtable` WHERE `public_key` = '$public_key' LIMIT 1");

        if (!$req)
        {
            // the connection may fail
            ?>{"err":"query failed"}<?php
            exit();
        }

        // has the certificate been revoked?
        $revoked = mysql_num_rows($req) > 0;

        // close the connection
        mysql_close($link);

        return $revoked;
    }
}

// this script expects a public key as a GET parameter.
if(!empty($_GET["pub"]))
{

    // we filter everything except for hexadecimal characters
    $public_key = preg_replace("/[^a-fA-F0-9]+/", "", $_GET["pub"]);

    // a public key in this representation has the length 32 * 2
    // (32 bytes with each 2 characters)
    if(strlen($public_key) == 32 * 2)
    {
        $revoked = is_revoked($public_key);

        ?>{"pub":"<?php echo $public_key; ?>","revoked":<?php echo $revoked ? "true" : "false"; ?>}<?php
    }
    else
    {
        // if the length is not 32*2, print this
        ?>{"err":"wrong len"}<?php
    }
}
else
{
    // if the parameter pub is empty, print this
    ?>{"err":"no pub given"}<?php
}
?>
