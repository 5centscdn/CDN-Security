<?php
$secret = 'secret_key';
$ip = '1.2.3.4';
$path = '/live/133529_2/chunklist.m3u8';
$expires = time() + 10000;
$link = "$expires$path$ip $secret";
$md5 = md5($link, true);
$md5 = base64_encode($md5);
$md5 = strtr($md5, '+/', '-_');
$md5 = str_replace('=', '', $md5);
$url = "http://cdn.site.com{$path}?md5={$md5}&expires={$expires}";
 echo $url;
 echo "\n";
