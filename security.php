<?php

/************************************************************************/
/* PHP Firewall: Firewall for WebSite                                   */
/* ============================================                         */
/* Write by 0xHunter                                                    */
/* Twitter: https://twitter.com/0xHunter                                */
/* E-mail: 0x1.hunt3r@gmail.com                                         */
/* Release version: 1.0                                                 */
/* Release date : 2022/02/28                                            */
/*                                                                      */
/************************************************************************/



/*=================Config=================*/
error_reporting(0);
define('REQUEST_URI', $_SERVER['REQUEST_URI']);
define('QUERY_STRING_GET', $_SERVER['QUERY_STRING']);
define('QUERY_STRING_POST', file_get_contents("php://input"));
define('HTTP_USER_AGENT', $_SERVER['HTTP_USER_AGENT']);
define('HTTP_HOST', $_SERVER['HTTP_HOST']);
define('REQUEST_METHOD', $_SERVER['REQUEST_METHOD']);
define('MAIL_NOTIFY', '0x1.hunter@gmail.com');
define('SEND_MAIL', false);
define('LOG_FILE', true);
/*=================End Config=================*/


/*=================Settings=================*/
if (PHP_FIREWALL_STATUS === true):

    function GET_IP()
    {
        // Get real IP
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
            $_SERVER['HTTP_CLIENT_IP'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }
        $client  = @$_SERVER['HTTP_CLIENT_IP'];
        $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
        $remote  = $_SERVER['REMOTE_ADDR'];

        if (filter_var($client, FILTER_VALIDATE_IP)) {
            $ip = $client;
        } elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
            $ip = $forward;
        } else {
            $ip = $remote;
        }

        return $ip;
    }

    /* Send a notification with log file to your e-mail */
    function push_email($subject, $msg)
    {
        $headers = "From: PHP Firewall: ".MAIL_NOTIFY." <".MAIL_NOTIFY.">\r\n"
        ."Reply-To: ".MAIL_NOTIFY."\r\n"
        ."Priority: urgent\r\n"
        ."Importance: High\r\n"
        ."Precedence: special-delivery\r\n"
        ."Organization: PHP Firewall\r\n"
        ."MIME-Version: 1.0\r\n"
        ."Content-Type: text/plain\r\n"
        ."Content-Transfer-Encoding: 8bit\r\n"
        ."X-Priority: 1\r\n"
        ."X-MSMail-Priority: High\r\n"
        ."X-Mailer: PHP/" . phpversion() ."\r\n"
        ."X-PHPFirewall: 1.0 by PHPFirewall\r\n"
        ."Date:" . date("D, d M Y H:s:i") . " +0100\n";
        if (MAIL_NOTIFY != '') {
            @mail(MAIL_NOTIFY, $subject, $msg, $headers);
        }
    }

    /* Create logs file and send it via mail */
    function PHP_LOGS($type)
    {
        if (LOG_FILE === true) {
            $f = fopen(dirname(__FILE__).'/logs.txt', 'a');
            $msg = date('j-m-Y H:i:s')." | $type | IP: ".GET_IP." ] | DNS: ".gethostbyaddr(GET_IP)." | Agent: ".HTTP_USER_AGENT." | URL: ".REQUEST_URI." | Referer: ".$_SERVER['GET_REFERER']."\n\n";
            fputs($f, $msg);
            fclose($f);
            if (SEND_MAIL === true) {
                push_email('Alert PHP Firewall '.strip_tags($_SERVER['SERVER_NAME']), "PHP Firewall logs of ".strip_tags($_SERVER['SERVER_NAME'])."\n".str_replace('|', "\n", $msg));
            }
        }
    }

/*=================End Settings=================*/


/*=================Check Protections=================*/

    /* Methods protection */
    if (preg_match('/^(HEAD|TRACE|TRACK|DEBUG|OPTIONS|PUT)/i', REQUEST_METHOD)) {
        PHP_LOGS("Method Protection: ".REQUEST_METHOD);
        die("This method is not supported !");
    }

    /* REFERER Protection */
    if (isset($_SERVER['HTTP_REFERER'])) {
        if (!stripos($_SERVER['HTTP_REFERER'], HTTP_HOST, 0)) {
            PHP_LOGS('REFERER Protection: '.$_SERVER['HTTP_REFERER']);
            die("Posting from other server is not allowed !");
        }
    }

    /* Input protection */
    function clean($input)
    {
        $search = array(
            '@<script[^>]*?>.*?</script>@si',
            '@<[\/\!]*?[^<>]*?>@si',
            '@<style[^>]*?>.*?</style>@siU',
            '@<![\s\S]*?--[ \t\n\r]*>@'
        );

        $output = preg_replace($search, '', $input);
        return $output;
    }

    $_POST    = clean($_POST);
    $_GET     = clean($_GET);
    $_REQUEST = clean($_REQUEST);
    $_COOKIE  = clean($_COOKIE);
    if (isset($_SESSION)) {
        $_SESSION = clean($_SESSION);
    }

    /* List of queries */
    $sql = array("'","from","where","concat","union","select","order","/**/","/*","*/","/*!","/*--*/","information_schema","table_schema","or 1=1","'1'='1","char","sleep(","%27");
    $xss = array("prompt(","<img","onclick","script","alert","document.cookies","javascript:","document.location");
    $php_commad = array("/etc/passwd","system","exec","exec_shell","file_put_contents","fopen","eval","fwrite","phpinfo","curl","wget");
    $LFI_RFI = array("../","./","..%2F",".%2F","%252f","%00","php://filter/","convert.base64-encode","zlib.deflate","data://text/","php:expect","php://input");
    /* List of user_agent bots */
    $kill_bots = array('@nonymouse', 'addresses.com', 'ideography.co.uk', 'adsarobot', 'ah-ha', 'aktuelles', 'alexibot', 'almaden', 'amzn_assoc', 'anarchie', 'art-online', 'aspseek', 'assort', 'asterias', 'attach', 'atomz', 'atspider', 'autoemailspider', 'backweb', 'backdoorbot', 'bandit', 'batchftp', 'bdfetch', 'big.brother', 'black.hole', 'blackwidow', 'blowfish', 'bmclient', 'boston project', 'botalot', 'bravobrian', 'buddy', 'bullseye', 'bumblebee ', 'builtbottough', 'bunnyslippers', 'capture', 'cegbfeieh', 'cherrypicker', 'cheesebot', 'chinaclaw', 'cicc', 'civa', 'clipping', 'collage', 'collector', 'copyrightcheck', 'cosmos', 'crescent', 'custo', 'cyberalert', 'deweb', 'diagem', 'digger', 'digimarc', 'diibot', 'directupdate', 'disco', 'dittospyder', 'download accelerator', 'download demon', 'download wonder', 'downloader', 'drip', 'dsurf', 'dts agent', 'dts.agent', 'easydl', 'ecatch', 'echo extense', 'efp@gmx.net', 'eirgrabber', 'elitesys', 'emailsiphon', 'emailwolf', 'envidiosos', 'erocrawler', 'esirover', 'express webpictures', 'extrac', 'eyenetie', 'fastlwspider', 'favorg', 'favorites sweeper', 'fezhead', 'filehound', 'filepack.superbr.org', 'flashget', 'flickbot', 'fluffy', 'frontpage', 'foobot', 'galaxyBot', 'generic', 'getbot ', 'getleft', 'getright', 'getsmart', 'geturl', 'getweb', 'gigabaz', 'girafabot', 'go-ahead-got-it', 'go!zilla', 'gornker', 'grabber', 'grabnet', 'grafula', 'green research', 'harvest', 'havindex', 'hhjhj@yahoo', 'hloader', 'hmview', 'homepagesearch', 'htmlparser', 'hulud', 'http agent', 'httpconnect', 'httpdown', 'http generic', 'httplib', 'httrack', 'humanlinks', 'ia_archiver', 'iaea', 'ibm_planetwide', 'image stripper', 'image sucker', 'imagefetch', 'incywincy', 'indy', 'infonavirobot', 'informant', 'interget', 'internet explore', 'infospiders',  'internet ninja', 'internetlinkagent', 'interneteseer.com', 'ipiumbot', 'iria', 'irvine', 'jbh', 'jeeves', 'jennybot', 'jetcar', 'joc web spider', 'jpeg hunt', 'justview', 'kapere', 'kdd explorer', 'kenjin.spider', 'keyword.density', 'kwebget', 'lachesis', 'larbin',  'laurion(dot)com', 'leechftp', 'lexibot', 'lftp', 'libweb', 'links aromatized', 'linkscan', 'link*sleuth', 'linkwalker', 'libwww', 'lightningdownload', 'likse', 'lwp','mac finder', 'mag-net', 'magnet', 'marcopolo', 'mass', 'mata.hari', 'mcspider', 'memoweb', 'microsoft url control', 'microsoft.url', 'midown', 'miixpc', 'minibot', 'mirror', 'missigua', 'mister.pix', 'mmmtocrawl', 'moget', 'mozilla/2', 'mozilla/3.mozilla/2.01', 'mozilla.*newt', 'multithreaddb', 'munky', 'msproxy', 'nationaldirectory', 'naverrobot', 'navroad', 'nearsite', 'netants', 'netcarta', 'netcraft', 'netfactual', 'netmechanic', 'netprospector', 'netresearchserver', 'netspider', 'net vampire', 'newt', 'netzip', 'nicerspro', 'npbot', 'octopus', 'offline.explorer', 'offline explorer', 'offline navigator', 'opaL', 'openfind', 'opentextsitecrawler', 'orangebot', 'packrat', 'papa foto', 'pagegrabber', 'pavuk', 'pbwf', 'pcbrowser', 'personapilot', 'pingalink', 'pockey', 'program shareware', 'propowerbot/2.14', 'prowebwalker', 'proxy', 'psbot', 'psurf', 'puf', 'pushsite', 'pump', 'qrva', 'quepasacreep', 'queryn.metasearch', 'realdownload', 'reaper', 'recorder', 'reget', 'replacer', 'repomonkey', 'rma', 'robozilla', 'rover', 'rpt-httpclient', 'rsync', 'rush=', 'searchexpress', 'searchhippo', 'searchterms.it', 'second street research', 'seeker', 'shai', 'sitecheck', 'sitemapper', 'sitesnagger', 'slysearch', 'smartdownload', 'snagger', 'spacebison', 'spankbot', 'spanner', 'spegla', 'spiderbot', 'spiderengine', 'sqworm', 'ssearcher100', 'star downloader', 'stripper', 'sucker', 'superbot', 'surfwalker', 'superhttp', 'surfbot', 'surveybot', 'suzuran', 'sweeper', 'szukacz/1.4', 'tarspider', 'takeout', 'teleport', 'telesoft', 'templeton', 'the.intraformant', 'thenomad', 'tighttwatbot', 'titan', 'tocrawl/urldispatcher','toolpak', 'traffixer', 'true_robot', 'turingos', 'turnitinbot', 'tv33_mercator', 'uiowacrawler', 'urldispatcherlll', 'url_spider_pro', 'urly.warning ', 'utilmind', 'vacuum', 'vagabondo', 'vayala', 'vci', 'visualcoders', 'visibilitygap', 'vobsub', 'voideye', 'vspider', 'w3mir', 'webauto', 'webbandit', 'web.by.mail', 'webcapture', 'webcatcher', 'webclipping', 'webcollage', 'webcopier', 'webcopy', 'webcraft@bea', 'web data extractor', 'webdav', 'webdevil', 'webdownloader', 'webdup', 'webenhancer', 'webfetch', 'webgo', 'webhook', 'web.image.collector', 'web image collector', 'webinator', 'webleacher', 'webmasters', 'webmasterworldforumbot', 'webminer', 'webmirror', 'webmole', 'webreaper', 'websauger', 'websaver', 'website.quester', 'website quester', 'websnake', 'websucker', 'web sucker', 'webster', 'webreaper', 'webstripper', 'webvac', 'webwalk', 'webweasel', 'webzip', 'wget', 'widow', 'wisebot', 'whizbang', 'whostalking', 'wonder', 'wumpus', 'wweb', 'www-collector-e', 'wwwoffle', 'wysigot', 'xaldon', 'xenu', 'xget', 'x-tractor', 'zeus');

    foreach ($sql as $sql_queries) {
        if (strpos(strtolower(QUERY_STRING_POST), strtolower($sql_queries)) !== false) {
            PHP_LOGS("POST: SQL Injection Detected !");
            die("Attack Detected !");
        }
        if (strpos(strtolower(QUERY_STRING_GET), strtolower($sql_queries)) !== false) {
            PHP_LOGS("GET: SQL Injection Detected !");
            die("Attack Detected !");
        }

        if (strpos(strtolower(HTTP_USER_AGENT), strtolower($sql_queries)) !== false) {
            PHP_LOGS("USER_AGENT: SQL Injection Detected !");
            die("Attack Detected !");
        }
    }

        foreach ($xss as $xss_queries) {
            if (strpos(strtolower(QUERY_STRING_GET), strtolower($xss_queries)) !== false) {
                PHP_LOGS("Cross-site scripting (XSS) Detected !");
                die("Attack Detected !");
            }
        }

        foreach ($php_command as $php_command_queries) {
            if (strpos(strtolower(QUERY_STRING_POST), strtolower($php_command_queries)) !== false) {
                PHP_LOGS("POST: PHP Command Detected !");
                die("Attack Detected !");
            }

            if (strpos(strtolower(QUERY_STRING_GET), strtolower($php_command_queries)) !== false) {
                PHP_LOGS("GET: PHP Command Detected !");
                die("Attack Detected !");
            }
        }

        foreach ($LFI_RFI as $LFI_RFI_queries) {
            if (strpos(strtolower(QUERY_STRING_GET), strtolower($LFI_RFI_queries)) !== false) {
                PHP_LOGS("GET: LFI Detected !");
                die("Attack Detected !");
            }

            if (strpos(strtolower(QUERY_STRING_POST), strtolower($LFI_RFI_queries)) !== false) {
                PHP_LOGS("POST: LFI Detected !");
                die("Attack Detected !");
            }
        }

    foreach ($kill_bots as $bots) {
        if (strpos(strtolower(HTTP_USER_AGENT), strtolower($bots)) !== false) {
            PHP_LOGS("Bot Detected !");
            die("Bot Detected !");
        }
    }


endif;
