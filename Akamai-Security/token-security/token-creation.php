 <?php
 require_once ‘AkamaiToken.php’;
 $secret = ‘secret key’;
 $path = ‘/demo/stream/playlist.m3u8’;
 $ttl = 300;
 $c = new Akamai_EdgeAuth_Config();
 $c->set_key(md5($secret));
 $c->set_acl(rtrim(pathinfo($path, PATHINFO_DIRNAME), ‘/’).‘/*’);
 $c->set_window($ttl);
 $g = new Akamai_EdgeAuth_Generate();
 $token = ‘hdnts=’.$g->generate_token($c);
 $url = “https://example.5centscdn.com{$path}?{$token}”;
 echo $url . “\n”;
?>
