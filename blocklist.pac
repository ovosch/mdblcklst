// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Tue, 05 Feb 2019 00:44:46 GMT
// Created with command: easylist_pac.py
//
// http://www.gnu.org/licenses/lgpl.txt
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy server.
//
// Influenced in part by code from King of the PAC from http://securemecca.com/pac.html

// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
// var blackhole_ip_port = "127.0.0.1:8119";  // ngnix-hosted blackhole
// var blackhole_ip_port = "8.8.8.8:53";      // GOOG DNS blackhole; do not use: no longer works with iOS 11—causes long waits on some sites
var blackhole_ip_port = "127.0.0.1:8119";    // on iOS a working blackhole requires return code 200;
// e.g. use the adblock2privoxy nginx server as a blackhole
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

// EasyList rules:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet
// https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
// https://adblockplus.org/blog/investigating-filter-matching-algorithms
// 
// Strategies to convert EasyList rules to Javascript tests:
// 
// In general:
// 1. Preference for performance over 1:1 EasyList functionality
// 2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
// 3. Exact matches: use Object hashing (very fast); use efficient NFA RegExp's for all else
// 4. Divide and conquer specific cases to avoid large RegExp's
// 5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
// 6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin
// 
// scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings
// 
// EasyList rules:
// 
// || domain anchor
// 
// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// 
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// 
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// 
// url parts e.g. a.b^c&d|
// 
// All cases RegExp.test(url)
// Except: |http://a.b. Treat these as domain anchors after stripping the scheme
// 
// regex e.g. /r/
// 
// All cases RegExp.test(url)
// 
// @@ exceptions
// 
// Flag as "good" versus "bad" default
// 
// Variable name conventions (example that defines the rule):
// 
// bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
// bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
// 
// 71 rules:
var good_da_host_JSON = { "apple.com": null,
"icloud.com": null,
"apple-dns.net": null,
"swcdn.apple.com": null,
"init.itunes.apple.com": null,
"init-cdn.itunes-apple.com.akadns.net": null,
"itunes.apple.com.edgekey.net": null,
"setup.icloud.com": null,
"p32-escrowproxy.icloud.com": null,
"p32-escrowproxy.fe.apple-dns.net": null,
"keyvalueservice.icloud.com": null,
"keyvalueservice.fe.apple-dns.net": null,
"p32-bookmarks.icloud.com": null,
"p32-bookmarks.fe.apple-dns.net": null,
"p32-ckdatabase.icloud.com": null,
"p32-ckdatabase.fe.apple-dns.net": null,
"configuration.apple.com": null,
"configuration.apple.com.edgekey.net": null,
"mesu.apple.com": null,
"mesu-cdn.apple.com.akadns.net": null,
"mesu.g.aaplimg.com": null,
"gspe1-ssl.ls.apple.com": null,
"gspe1-ssl.ls.apple.com.edgekey.net": null,
"api-glb-bos.smoot.apple.com": null,
"query.ess.apple.com": null,
"query-geo.ess-apple.com.akadns.net": null,
"query.ess-apple.com.akadns.net": null,
"setup.fe.apple-dns.net": null,
"gsa.apple.com": null,
"gsa.apple.com.akadns.net": null,
"icloud-content.com": null,
"usbos-edge.icloud-content.com": null,
"usbos.ce.apple-dns.net": null,
"lcdn-locator.apple.com": null,
"lcdn-locator.apple.com.akadns.net": null,
"lcdn-locator-usuqo.apple.com.akadns.net": null,
"cl1.apple.com": null,
"cl2.apple.com": null,
"cl3.apple.com": null,
"cl4.apple.com": null,
"cl5.apple.com": null,
"cl1-cdn.origin-apple.com.akadns.net": null,
"cl2-cdn.origin-apple.com.akadns.net": null,
"cl3-cdn.origin-apple.com.akadns.net": null,
"cl4-cdn.origin-apple.com.akadns.net": null,
"cl5-cdn.origin-apple.com.akadns.net": null,
"cl1.apple.com.edgekey.net": null,
"cl2.apple.com.edgekey.net": null,
"cl3.apple.com.edgekey.net": null,
"cl4.apple.com.edgekey.net": null,
"cl5.apple.com.edgekey.net": null,
"xp.apple.com": null,
"xp.itunes-apple.com.akadns.net": null,
"mt-ingestion-service-pv.itunes.apple.com": null,
"p32-sharedstreams.icloud.com": null,
"p32-sharedstreams.fe.apple-dns.net": null,
"p32-fmip.icloud.com": null,
"p32-fmip.fe.apple-dns.net": null,
"gsp-ssl.ls.apple.com": null,
"gsp-ssl.ls-apple.com.akadns.net": null,
"gsp-ssl.ls2-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com": null,
"gspe35-ssl.ls-apple.com.akadns.net": null,
"gspe35-ssl.ls.apple.com.edgekey.net": null,
"gsp64-ssl.ls.apple.com": null,
"gsp64-ssl.ls-apple.com.akadns.net": null,
"mt-ingestion-service-st11.itunes.apple.com": null,
"mt-ingestion-service-st11.itunes-apple.com.akadns.net": null,
"microsoft.com": null,
"mozilla.com": null,
"mozilla.org": null };
var good_da_host_exact_flag = 71 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_hostpath_JSON = {  };
var good_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^$/;
var good_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_RegExp = /^$/;
var good_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 39 rules:
var good_da_host_exceptions_JSON = { "iad.apple.com": null,
"iadsdk.apple.com": null,
"iadsdk.apple.com.edgekey.net": null,
"bingads.microsoft.com": null,
"azure.bingads.trafficmanager.net": null,
"choice.microsoft.com": null,
"choice.microsoft.com.nsatc.net": null,
"corpext.msitadfs.glbdns2.microsoft.com": null,
"corp.sts.microsoft.com": null,
"df.telemetry.microsoft.com": null,
"diagnostics.support.microsoft.com": null,
"feedback.search.microsoft.com": null,
"i1.services.social.microsoft.com": null,
"i1.services.social.microsoft.com.nsatc.net": null,
"redir.metaservices.microsoft.com": null,
"reports.wes.df.telemetry.microsoft.com": null,
"services.wes.df.telemetry.microsoft.com": null,
"settings-sandbox.data.microsoft.com": null,
"settings-win.data.microsoft.com": null,
"sqm.df.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com": null,
"sqm.telemetry.microsoft.com.nsatc.net": null,
"statsfe1.ws.microsoft.com": null,
"statsfe2.update.microsoft.com.akadns.net": null,
"statsfe2.ws.microsoft.com": null,
"survey.watson.microsoft.com": null,
"telecommand.telemetry.microsoft.com": null,
"telecommand.telemetry.microsoft.com.nsatc.net": null,
"telemetry.urs.microsoft.com": null,
"vortex.data.microsoft.com": null,
"vortex-sandbox.data.microsoft.com": null,
"vortex-win.data.microsoft.com": null,
"cy2.vortex.data.microsoft.com.akadns.net": null,
"watson.microsoft.com": null,
"watson.ppe.telemetry.microsoft.comwatson.telemetry.microsoft.com": null,
"watson.telemetry.microsoft.com.nsatc.net": null,
"wes.df.telemetry.microsoft.com": null,
"win10.ipv6.microsoft.com": null,
"www.bingads.microsoft.com": null };
var good_da_host_exceptions_exact_flag = 39 > 0 ? true : false;  // test for non-zero number of rules

// 2050 rules:
var bad_da_host_JSON = { "instagram.com": null,
"delfi.lv": null,
"tjournal.ru": null,
"cdninstagram.com": null,
"fna.fbcdn.net": null,
"cameleo.xyz": null,
"0s.o53xo.nfxhg5dbm5zgc3jomnxw2.cmle.ru": null,
"croxyproxy.com": null,
"awsbox.xyz": null,
"spottyhub.site": null,
"sourcelab.icu": null,
"bluecdn.info": null,
"hmway.top": null,
"storiesig.com": null,
"varlamov.ru": null,
"meduza.io": null,
"mysku.ru": null,
"twitter.com": null };
var bad_da_host_exact_flag = 2050 > 0 ? true : false;  // test for non-zero number of rules

// 9 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:tracker(?=([\s\S]*?\.richcasino\.com))\1|imgadult\.com(?=([\s\S]*?))\2|imgtaxi\.com(?=([\s\S]*?))\3|imgwallet\.com(?=([\s\S]*?))\4|images\.(?=([\s\S]*?\.criteo\.net))\5|analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\6|imgdrive\.net(?=([\s\S]*?))\7|rcm(?=([\s\S]*?\.amazon\.))\8|stats\-(?=([\s\S]*?\.p2pnow\.ru))\9)/i;
var bad_da_host_regex_flag = 9 > 0 ? true : false;  // test for non-zero number of rules

// 613 rules:
var bad_da_hostpath_JSON = { "nydailynews.com/tracker.js": null,
"depositfiles.com/stats.php": null,
"ad.atdmt.com/i/a.html": null,
"google-analytics.com/analytics.js": null,
"ad.atdmt.com/i/a.js": null,
"facebook.com/plugins/like.php": null,
"facebook.com/plugins/page.php": null,
"assets.pinterest.com/js/pinit.js": null,
"googletagmanager.com/gtm.js": null,
"facebook.com/plugins/likebox.php": null,
"imagesnake.com/includes/js/pops.js": null,
"baidu.com/js/log.js": null,
"domaintools.com/tracker.php": null,
"hulkshare.com/stats.php": null,
"linkconnector.com/traffic_record.php": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"windows.net/script/p.js": null,
"autoline-top.com/counter.php": null,
"cloudfront.net/analytics.js": null,
"elb.amazonaws.com/partner.gif": null,
"viglink.com/images/pixel.gif": null,
"twitvid.com/api/tracking.php": null,
"facebook.com/common/scribe_endpoint.php": null,
"disqus.com/stats.html": null,
"cloudfront.net/log.js": null,
"facebook.com/plugins/share_button.php": null,
"movad.de/c.ount": null,
"myway.com/gca_iframe.html": null,
"plista.com/iframeShowItem.php": null,
"freebunker.com/includes/js/cat.js": null,
"videowood.tv/assets/js/popup.js": null,
"dpstatic.com/banner.png": null,
"amazonaws.com/g.aspx": null,
"sltrib.com/csp/mediapool/sites/Shared/assets/csp/includes/omniture/SiteCatalystCode_H_17.js": null,
"baidu.com/h.js": null,
"allmyvideos.net/player/ova-jw.swf": null,
"hitleap.com/assets/banner.png": null,
"codecguide.com/stats.js": null,
"thefile.me/apu.php": null,
"cloudfront.net/scripts/js3caf.js": null,
"eastmoney.com/counter.js": null,
"brightcove.com/1pix.gif": null,
"cloudfront.net/scripts/cookies.js": null,
"baymirror.com/static/img/bar.gif": null,
"eageweb.com/stats.php": null,
"googletagservices.com/dcm/dcmads.js": null,
"linkwithin.com/pixel.png": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"google-analytics.com/siteopt.js": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"turboimagehost.com/p1.js": null,
"cloudfront.net/js/reach.js": null,
"slashdot.org/images/js.gif": null,
"nyafilmer.com/wp-content/themes/keremiya1/js/script.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"piano-media.com/bucket/novosense.swf": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"pimpandhost.com/static/html/wide_iframe.html": null,
"nrj-play.fr/js/social.js": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"zylom.com/pixel.jsp": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"military.com/data/popup/new_education_popunder.htm": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"ulogin.ru/js/stats.js": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"statravel.co.uk/static/uk_division_web_live/Javascript/wt_gets.js": null,
"pimpandhost.com/static/html/iframe.html": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"video44.net/gogo/yume-h.swf": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"skyrock.net/js/stats_blog.js": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"fncstatic.com/static/all/js/geo.js": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"phonearena.com/_track.php": null,
"google-analytics.com/ga_exp.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"cdnplanet.com/static/rum/rum.js": null,
"redtube.com/js/track.js": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"btkitty.org/static/images/880X60.gif": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"assets.pinterest.com/pidget.html": null,
"sexier.com/services/adsredirect.ashx": null,
"streams.tv/js/bn5.js": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"store.yahoo.net/lib/directron/icons-test02.jpg": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"ino.com/img/sites/mkt/click.gif": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"mailjet.com/statics/js/widget.modal.js": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"picturevip.com/imagehost/top_banners.html": null,
"belfasttelegraph.co.uk/editorial/web/survey/recruit-div-img.js": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"swatchseries.to/bootstrap.min.js": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"harpercollins.co.uk/js/cookie.js": null,
"ibtimes.com/player/stats.swf": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"watchuseek.com/media/clerc-final.jpg": null,
"attorrents.com/static/images/download3.png": null,
"google-analytics.com/cx/api.js": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"images.military.com/pixel.gif": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"dexerto.com/app/uploads/2016/11/Gfuel-LemoNade.jpg": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"expressen.se/static/scripts/s_code.js": null,
"skyrock.net/img/pix.gif": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"statig.com.br/pub/setCookie.js": null,
"razor.tv/site/servlet/tracker.jsp": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"watchuseek.com/media/wus-image.jpg": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"newsarama.com/social.php": null,
"kitco.com/ssi/dmg_banner_001.stm": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"sofascore.com/geoip.js": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"kleisauke.nl/static/img/bar.gif": null,
"cloudfront.net/track.html": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"lightboxcdn.com/static/identity.html": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"btkitty.com/static/images/880X60.gif": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"cdn.cdncomputer.com/js/main.js": null,
"shopify.com/track.js": null,
"sharesix.com/a/images/watch-bnr.gif": null,
"sexvideogif.com/msn.js": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"wired.com/tracker.js": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"freedoflondon.com/Styles/dialog-popup/jquery-ui.js": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"atom-data.io/session/latest/track.html": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"uploadlw.com/js/cash.js": null,
"assets.tumblr.com/assets/html/iframe/teaser.html": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"v.blog.sohu.com/dostat.do": null,
"swiftypecdn.com/cc.js": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"cardstore.com/affiliate.jsp": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"s-msn.com/br/gbl/js/2/report.js": null,
"youwatch.org/vod-str.html": null,
"myanimelist.net/static/logging.html": null,
"merchantcircle.com/static/track.js": null,
"videoszoofiliahd.com/wp-content/themes/vz/js/p.js": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"india.com/ads/jw/ova-jw.swf": null,
"pubarticles.com/add_hits_by_user_click.php": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"elb.amazonaws.com/small.gif": null,
"go4up.com/assets/img/download-button.png": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"assets.tumblr.com/assets/html/iframe/o.html": null,
"letswatchsomething.com/images/filestreet_banner.jpg": null,
"cash9.org/assets/img/banner2.gif": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"wagital.com/Wagital-Ads.html": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"optimizely.com/js/geo.js": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17janE.gif": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17sepB.gif": null,
"pimpandhost.com/images/pah-download.gif": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"makeagif.com/parts/fiframe.php": null,
"rlsbb.com/wp-content/uploads/smoke.jpg": null,
"watch-movies.net.in/popup.php": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"rackcdn.com/knotice.api.js": null,
"xxxselected.com/cdn_files/dist/js/blockPlaces.js": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"watchseries.eu/js/csspopup.js": null,
"fileom.com/img/instadownload2.png": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"watchseries.eu/images/download.png": null,
"twitvid.com/mediaplayer/players/tracker.swf": null,
"js.static.m1905.cn/pingd.js": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"playgirl.com/pg/media/prolong_ad.png": null,
"viralogy.com/javascript/viralogy_tracker.js": null,
"cv.ee/static/stat.php": null,
"google-analytics.com/internal/analytics.js": null,
"ablacrack.com/popup-pvd.js": null,
"apis.google.com/js/platform.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"cur.lv/bootstrap/js/bootstrapx-clickover.js": null,
"blog.co.uk/script/blogs/afc.js": null,
"watchseries.eu/images/affiliate_buzz.gif": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"netzero.net/account/event.do": null,
"playomat.de/sfye_noscript.php": null,
"machovideo.com/img/site/postimg2/rotate.php": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"medorgs.ru/js/counterlog_img.js": null,
"edvantage.com.sg/site/servlet/tracker.jsp": null,
"magicaffiliateplugin.com/img/mga-125x125.gif": null,
"d27s92d8z1yatv.cloudfront.net/js/jquery.jw.analitycs.js": null,
"imgdino.com/gsmpop.js": null,
"youserials.com/i/banner_pos.jpg": null,
"rlsbb.com/wp-content/uploads/izilol.gif": null,
"amazonaws.com/ad_w_intersitial.html": null,
"mail.yahoo.com/mc/md.php": null,
"judgeporn.com/video_pop.php": null,
"hdfree.tv/ad.html": null,
"cdnmaster.com/sitemaster/sm360.js": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"washingtonpost.com/wp-srv/wapolabs/dw/readomniturecookie.html": null,
"tube18.sex/player/html.php": null,
"downloadian.com/assets/banner.jpg": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"secureupload.eu/gfx/SecureUpload_Banner.png": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null,
"vipi.tv/ad.php": null,
"ph.hillcountrytexas.com/imp.php": null,
"cloudzilla.to/cam/wpop.php": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"literatureandlatte.com/gfx/buynowaffiliate.jpg": null,
"boobieblog.com/submityourbitchbanner3.jpg": null,
"uptobox.com/images/downloaden.gif": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"file.org/fo/scripts/download_helpopt.js": null,
"hornywhores.net/img/double.jpg": null,
"milanofinanza.it/img/top.png": null,
"pinterest.com/v1/urls/count.json": null,
"foodingredientsfirst.com/content/flash_loaders/loadlargetile.swf": null,
"trutv.com/includes/mods/iframes/mgid-blog.php": null,
"mailmax.co.nz/login/open.php": null,
"arstechnica.com/dragons/breath.gif": null,
"thevideo.me/mba/cds.js": null,
"kuiken.co/static/w.js": null,
"paper.li/javascripts/analytics.js": null,
"facebook.com/offsite_event.php": null,
"xcams.com/livecams/pub_collante/script.php": null,
"lazygirls.info/click.php": null,
"englishgrammar.org/images/30off-coupon.png": null,
"hulu.com/google_conversion_video_view_tracking.html": null,
"dirittierisposte.it/Images/corriere_sera.png": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"mozilla.com/js/track.js": null,
"analpornpix.com/agent.php": null,
"radioreference.com/i/p4/tp/smPortalBanner.gif": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"kitguru.net/wp-content/wrap.jpg": null,
"binsearch.info/iframe.php": null,
"rtlradio.lu/stats.php": null,
"fileom.com/img/downloadnow.png": null,
"elgg.org/images/hostupon_banner.gif": null,
"mycams.com/freechat.php": null,
"hwbot.org/banner.img": null,
"guim.co.uk/guardian/thirdparty/tv-site/side.html": null,
"eurotrucksimulator2.com/images/logo_blog.png": null,
"hunstoncanoeclub.co.uk/media/system/js/modal.js": null,
"js.adv.dadapro.net/collector.js/prcy.js": null,
"divxstage.eu/images/download.png": null,
"watchfree.to/topright.php": null,
"ltfm.ca/stats.php": null,
"naughtyblog.org/pr1pop.js": null,
"beyond.com/common/track/trackgeneral.asp": null,
"adultmastercash.com/e1.php": null,
"onsugar.com/static/ck.php": null,
"international-property.countrylife.co.uk/js/search_widget.js": null,
"hornywhores.net/img/zevera_rec.jpg": null,
"redtube.com/_status/pix.php": null,
"yahoo.com/ysmload.html": null,
"witbankspurs.co.za/layout_images/sponsor.jpg": null,
"youdao.com/imp/cac.js": null,
"messianictimes.com/images/Israel%20Today%20Logo.png": null,
"jayisgames.com/maxcdn_160x250.png": null,
"legalbusinessonline.com/popup/albpartners.aspx": null,
"sportingbet.com.au/sbacontent/puntersparadise.html": null,
"niggasbelike.com/wp-content/themes/zeecorporate/images/b.jpg": null,
"stupid.news/Javascripts/Abigail.js": null,
"bit.no.com/assets/images/bity.png": null,
"ecustomeropinions.com/survey/nojs.php": null,
"flyordie.com/games/online/ca.html": null,
"onegameplace.com/iframe.php": null,
"lijit.com/adif_px.php": null,
"fujifilm.com/js/shared/analyzer.js": null,
"uramov.info/wav/wavideo.html": null,
"5star-shareware.com/scripts/5starads.js": null,
"vwdealerdigital.com/cdn/sd.js": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"shareit.com/affiliate.html": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"aaugh.com/images/dreamhostad.gif": null,
"yourbittorrent.com/downloadnow.png": null,
"hsn.com/code/pix.aspx": null,
"trackjs.com/usage.gif": null,
"watchuseek.com/flashwatchwus.swf": null,
"cloudfront.net/js/ca.js": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"windowsphone.com/scripts/siteTracking.js": null,
"centralscotlandjoinery.co.uk/images/csj-125.gif": null,
"amazonaws.com/accio-lib/accip_script.js": null,
"cbc.ca/video/bigbox.html": null,
"24video.net/din_new6.php": null,
"kxcdn.com/track.js": null,
"droidnetwork.net/img/dt-atv160.jpg": null,
"newstatesman.com/js/NewStatesmanSDC.js": null,
"gameforge.de/init.gif": null,
"wiilovemario.com/images/fc-twin-play-nes-snes-cartridges.png": null,
"intel.com/sites/wap/global/wap.js": null,
"bets4free.co.uk/content/5481b452d9ce40.09507031.jpg": null,
"enigmagroup.org/clients/privatetunnels.swf": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"script.idgentertainment.de/gt.js": null,
"pcmag.com/blogshome/logicbuy.js": null,
"filmlinks4u.net/twatch/jslogger.php": null,
"bc.vc/adbcvc.html": null,
"godaddy.com/pageevents.aspx": null,
"stats.screenresolution.org/get.php": null,
"rightmove.co.uk/ps/images/logging/timer.gif": null,
"24.com//flashplayer/ova-jw.swf": null,
"alluremedia.com.au/s/au.js": null,
"tfl.gov.uk/tfl-global/scripts/stats-config.js": null,
"dict.cc/img/fbplus1.png": null,
"facebook.com/widgets/recommendations.php": null,
"scotts.com/smg/js/omni/customTracking.js": null,
"intellicast.com/travel/cheapflightswidget.htm": null,
"icxm.net/x/img/kinguin.jpg": null,
"breakingburner.com/stats.html": null,
"facebook.com/whitepages/wpminiprofile.php": null,
"nih.gov/share/scripts/survey.js": null,
"villagevoice.com/img/VDotDFallback-large.gif": null,
"go4up.com/assets/img/downloadbuttoned.png": null,
"megashares.com/cache_program_banner.html": null,
"ufonts.com/gfx/uFonts_Banner5.png": null,
"validome.org/valilogger/track.js": null,
"collegehumor.com/track.php": null,
"d-h.st/assets/img/download1.png": null,
"godisageek.com/amazon.png": null,
"imghost.us.to/xxx/content/system/js/iframe.html": null,
"videolan.org/images/events/animated_packliberte.gif": null,
"s3.amazonaws.com/dmas-public/rubicon/bundle.js": null,
"makantime.tv/analytics.js": null,
"nabble.com/static/analytics.js": null,
"server4.pro/images/banner.jpg": null,
"infochoice.com.au/Handler/WidgetV2Handler.ashx": null,
"techbargains.com/scripts/banner.js": null,
"boobieblog.com/TilaTequilaBackdoorBanner2.jpg": null,
"go4up.com/assets/img/d0.png": null,
"imgbabes.com/ero-foo.html": null,
"vixy.net/fb-traffic-pop.js": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"nyteknik.se/ver02/javascript/2012_s_code_global.js": null,
"qbn.com/media/static/js/ga.js": null,
"livescore.in/res/image/bookmaker-list.png": null,
"2mdn.net/dot.gif": null,
"moviesrox.tech/banner.png": null,
"dump8.com/js/stat.php": null,
"streamlive.to/images/iptv.png": null,
"medscape.com/pi/1x1/pv/profreg-1x1.gif": null,
"hqtubevideos.com/play.html": null,
"vimeocdn.com/js_opt/ablincoln_combined.min.js": null,
"free.fr/cgi-bin/wwwcount.cgi": null,
"streamlive.to/images/movies10.png": null,
"theconversation.com/javascripts/lib/content_tracker_hook.js": null,
"vbs.tv/tracker.html": null,
"platform.twitter.com/impressions.js": null,
"oodle.com/js/suntracking.js": null,
"outlookmoney.com/sharekhan_ad.jpg": null,
"surveymonkey.com/jspop.aspx": null,
"ntmb.de/count.html": null,
"hdm-stuttgart.de/count.cgi": null,
"techotopia.com/TechotopiaFiles/contextsky1.html": null,
"techotopia.com/TechotopiaFiles/contextsky2.html": null,
"swiftypecdn.com/te.js": null,
"dealnews.com/lw/ul.php": null,
"military.com/cgi-bin/redlog2.cgi": null,
"astronomy.com/sitefiles/overlays/overlaygenerator.aspx": null,
"on.net/images/gon_nodestore.jpg": null,
"video.syfy.com/lg.php": null,
"ibrod.tv/ib.php": null,
"domainit.com/scripts/track.js": null,
"shortnews.de/iframes/view_news.cfm": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"frozen-roms.in/popup.php": null,
"dp.ru/counter.gif": null,
"messianictimes.com/images/4-13/reach.jpg": null,
"racebets.com/media.php": null,
"gstatic.com/gadf/ga_dyn.js": null,
"limetorrentlinkmix.com/rd18/dop.js": null,
"gsprating.com/gap/image.php": null,
"radio-canada.ca/lib/TrueSight/markerFile.gif": null,
"ch131.so/images/2etio.gif": null,
"digiland.it/count.cgi": null,
"frozen-roms.me/popup.php": null,
"crazy-torrent.com/web/banner/online.jpg": null,
"facebook.com/xti.php": null,
"scriptcopy.com/tpl/phplb/search.jpg": null,
"3dsemulator.org/img/download.png": null,
"vcnewsdaily.com/images/vcnews_right_banner.gif": null,
"live-medias.net/button.php": null,
"wsj.net/MW5/content/analytics/hooks.js": null,
"yourbittorrent.com/images/lumovies.js": null,
"yahoo.com/perf.gif": null,
"1whois.org/static/popup.js": null,
"ovfile.com/player/jwadplugin.swf": null,
"vk.com/share.php": null,
"gammasites.com/pornication/pc_browsable.php": null,
"blacklistednews.com/images/KFC.png": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"pluso.ru/counter.php": null,
"atlantis.com/_scripts/tsedge/pagemarker.gif": null,
"facebook.com/email_open_log_pic.php": null,
"devilgirls.co/images/devil.gif": null,
"search.stream.cr/core/webfonts.js": null,
"buzzamedia.com/js/track.js": null,
"pornshare.biz/2.js": null,
"odnaknopka.ru/stat.js": null,
"uts-rss.crystalmedianetworks.com/track.php": null,
"egg.com/rum/data.gif": null,
"facebook.com/plugins/facepile.php": null,
"searchyc-naity.ru/analytics.js": null,
"abusewith.us/banner.gif": null,
"bdstatic.com/linksubmit/push.js": null,
"marketnewsvideo.com/etfchannel/evfad1.gif": null,
"intoday.in/btstryad.html": null,
"flightradar24.com/_includes/sections/airportAd.php": null,
"infogr.am/js/metrics.js": null,
"ultimatewindowssecurity.com/images/patchzone-resource-80x490.jpg": null,
"anews.com/s/js/widget.js": null,
"sap.com/global/ui/js/trackinghelper.js": null,
"scriptmafia.org/banner.gif": null,
"xvideohost.com/hor_banner.php": null,
"propakistani.pk/wp-content/themes/propakistani/images/776.jpg": null,
"friday-ad.co.uk/banner.js": null,
"o.aolcdn.com/js/mg1.js": null,
"overclock3d.net/img/pcp.jpg": null,
"filedino.com/imagesn/downloadgif.gif": null,
"hackingchinese.com/media/hellochinese.jpg": null,
"hackingchinese.com/media/skritter5.jpg": null,
"cdnprk.com/scripts/js3.js": null,
"hackingchinese.com/media/pleco.png": null,
"hackingchinese.com/media/hcw4.png": null,
"crackdb.com/img/vpn.png": null,
"torrentdownloads.me/templates/new/images/download_button2.jpg": null,
"experiandirect.com/javascripts/tracking.js": null,
"tabloidmedia.co.za/images/signs2.swf": null,
"torrentdownloads.me/templates/new/images/download_button3.jpg": null,
"speedvideo.net/img/playerFk.gif": null,
"playtowerdefensegames.com/ptdg-gao-gamebox-homepage.swf": null,
"projectfreetv.at/prom2.html": null,
"stargames.com/bridge.asp": null,
"amazonaws.com/amacrpr/crpr.js": null,
"go4up.com/assets/img/buttoned.gif": null,
"imgur.com/include/zedoinviewstub1621.html": null,
"kentonline.co.uk/weatherimages/SEW.jpg": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"vk.com/widget_community.php": null,
"greyorgray.com/images/hdtv-genie-gog.jpg": null,
"blacklistednews.com/images/July31stPRO.PNG": null,
"kentonline.co.uk/weatherimages/Britelite.gif": null,
"dailytrust.info/images/dangote.swf": null,
"seesaawiki.jp/img/rainman.gif": null,
"subs4free.com/_pop_link.php": null,
"flixist.com/img2.phtml": null,
"search.triadcars.news-record.com/autos/widgets/featuredautos.php": null,
"jheberg.net/img/mp.png": null,
"get-bitcoins-free.eu/img/blackred728smallsize.gif": null,
"destructoid.com/img2.phtml": null,
"johnbridge.com/vbulletin/banner_rotate.js": null,
"animeflavor.com/animeflavor-gao-gamebox.swf": null,
"clickfunnels.com/assets/pushcrew.js": null,
"wallpaperstock.net/partners.js": null,
"adrive.com/images/fc_banner.jpg": null,
"facebook.com/widgets/fan.php": null,
"mywot.net/files/wotcert/vipre.png": null,
"sockshare.com/moo.php": null,
"flashscore.com/res/image/bookmaker-list.png": null,
"tusfiles.net/images/tusfilesb.gif": null,
"t3.com/js/trackers.js": null,
"facebook.com/plugins/send.php": null,
"ytn.co.kr/_comm/ylog.php": null,
"godaddy.com/js/gdwebbeacon.js": null,
"thevideo.me/js/jspc.js": null,
"thevideo.me/js/jsmpc.js": null,
"facebook.com/brandlift.php": null,
"twitter.com/oct.js": null,
"cloudfront.net/powr.js": null,
"pcp001.com/media/globalPixel.js": null,
"ecostream.tv/js/pu.js": null,
"sporcle.com/adn/yaktrack.php": null,
"tortoise.proboards.com/tortoise.pl": null,
"babylon.com/site/images/common.js": null,
"badjojo.com/js/tools.js": null,
"filepost.com/default_popup.html": null,
"pornwikileaks.com/adultdvd.com.jpg": null,
"lederer.nl/incl/stats.js.php": null,
"isitnormal.com/img/iphone_hp_promo_wide.png": null,
"viator.com/analytics/percent_mobile_hash.js": null,
"platform.twitter.com/anywhere.js": null,
"osalt.com/js/track.js": null,
"ninja-copy.com/js/track.js": null,
"niknok.ru/count.asp": null,
"papajohns.com/index_files/activityi.html": null,
"nesn.com/img/nesn-nation/header-dunkin.jpg": null,
"stad.com/googlefoot2.php": null,
"ind.sh/view.php": null,
"extremeoverclocking.com/template_images/it120x240.gif": null,
"playfooty.tv/jojo.html": null,
"linguee.fr/white_pixel.gif": null,
"pourquoidocteur.fr/img2/face.png": null,
"boards.ie/timing.php": null,
"washingtonexaminer.com/house_creative.php": null,
"lolbin.net/stats.php": null,
"freeads.co.uk/ctx.php": null,
"cloudfront.net/dfpd.js": null,
"diplodocs.com/shopping/sol.js": null,
"thenewage.co.za/Image/kingprice.gif": null,
"3pmpickup.com.au/images/kmart_v2.jpg": null,
"mybetting.co.uk/twitter.png": null,
"redbunker.net/images/redb/redyeni.gif": null,
"cdn-surfline.com/home/billabong-xxl.png": null,
"torrentv.org/images/tsdd.jpg": null,
"torrentv.org/images/tsdls.jpg": null,
"freeminecraft.me/mw3.png": null,
"satnews.com/images/MITEQ_sky.jpg": null,
"oureducation.in/images/add.jpg": null,
"crazy-torrent.com/web/banner/0xxx0.net.jpg": null,
"2pass.co.uk/img/avanquest2013.gif": null,
"gamepressure.com/ajax/f2p.asp": null,
"mediaticks.com/bollywood.jpg": null,
"events.walla.co.il/events.asp": null,
"complexmedianetwork.com/js/cmnUNT.js": null,
"gonzagamer.com/uci/popover.js": null,
"widgethost.com/pax/counter.js": null,
"wwbf.com/b/topbanner.htm": null,
"monstertube.com/images/bottom-features.jpg": null,
"digital-zoom.de/counter.js": null,
"nike.com/cms/analytics-store-desktop.js": null,
"pornizer.com/_Themes/javascript/cts.js": null,
"imagefap.com/ajax/uass.php": null,
"financialnewsandtalk.com/scripts/slideshow-sponsors.js": null,
"next.co.uk/log.php": null,
"irishtimes.com/assets/js/notify.js": null,
"onlinepresse.info/counter.php": null,
"mp3s.su/uploads/___/djz_to.png": null,
"bbvms.com/zone/js/zonestats.js": null,
"seaporn.org/scripts/life.js": null,
"bc.vc/images/megaload.gif": null,
"messianictimes.com/images/MJBI.org.gif": null,
"take2.co.za/misc/bannerscript.php": null,
"plsn.com/images/PLSN-Bg1.jpg": null,
"socaseiras.com.br/banners.php": null,
"libero.it/cgi-bin/cdcounter.cgi": null,
"imageporter.com/ro-7bgsd.html": null,
"feed4u.info/feedipop.js": null,
"libero.it/cgi-bin/cdcountersp.cgi": null,
"mybetting.co.uk/facebook.png": null,
"tfl.gov.uk/tfl-global/scripts/stats.js": null,
"sourceforge.net/images/mlopen_post.html": null,
"dailyfreegames.com/js/partners.html": null };
var bad_da_hostpath_exact_flag = 613 > 0 ? true : false;  // test for non-zero number of rules
    
// 499 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:piano\-media\.com\/uid\/|pornfanplace\.com\/js\/pops\.|pinterest\.com\/images\/|doubleclick\.net\/adx\/|google\-analytics\.com\/plugins\/|quantserve\.com\/pixel\/|baidu\.com\/pixel|nydailynews\.com\/img\/sponsor\/|porntube\.com\/adb\/|reddit\.com\/static\/|adf\.ly\/_|jobthread\.com\/t\/|netdna\-ssl\.com\/tracker\/|adform\.net\/banners\/|baidu\.com\/ecom|imageshack\.us\/ads\/|freakshare\.com\/banner\/|adultfriendfinder\.com\/banners\/|widgetserver\.com\/metrics\/|amazonaws\.com\/analytics\.|platform\.twitter\.com\/js\/button\.|google\-analytics\.com\/gtm\/js|oload\.tv\/log|facebook\.com\/tr|chaturbate\.com\/affiliates\/|openload\.co\/log|channel4\.com\/ad\/|streamango\.com\/log|doubleclick\.net\/adj\/|fwmrm\.net\/ad\/|google\.com\/analytics\/|addthiscdn\.com\/live\/|view\.atdmt\.com\/partner\/|domaintools\.com\/partners\/|redtube\.com\/stats\/|barnebys\.com\/widgets\/|adultfriendfinder\.com\/javascript\/|imagecarry\.com\/down|cursecdn\.com\/banner\/|cloudfront\.net\/track|visiblemeasures\.com\/log|twitter\.com\/javascripts\/|adultfriendfinder\.com\/go\/|pop6\.com\/banners\/|voyeurhit\.com\/contents\/content_sources\/|mediaplex\.com\/ad\/js\/|wtprn\.com\/sponsors\/|facebook\.com\/connect\/|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|xvideos\-free\.com\/d\/|imagetwist\.com\/banner\/|wupload\.com\/referral\/|deadspin\.com\/sp\/|propelplus\.com\/track\/|veeseo\.com\/tracking\/|4tube\.com\/iframe\/|yandex\.st\/share\/|yahoo\.com\/beacon\/|yahoo\.com\/track\/|slashgear\.com\/stats\/|sextronix\.com\/images\/|healthtrader\.com\/banner\-|siberiantimes\.com\/counter\/|nydailynews\.com\/PCRichards\/|sex\.com\/popunder\/|thrixxx\.com\/affiliates\/|cloudfront\.net\/twitter\/|topbucks\.com\/popunder\/|pornoid\.com\/contents\/content_sources\/|video\-cdn\.abcnews\.com\/ad_|exitintel\.com\/log\/|github\.com\/_stats|hothardware\.com\/stats\/|doubleclick\.net\/ad\/|xxxhdd\.com\/contents\/content_sources\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|powvideo\.net\/ban\/|red\-tube\.com\/popunder\/|primevideo\.com\/uedata\/|hstpnetwork\.com\/ads\/|pornalized\.com\/contents\/content_sources\/|doubleclick\.net\/pixel|soufun\.com\/stats\/|adroll\.com\/pixel\/|photobucket\.com\/track\/|shareasale\.com\/image\/|zawya\.com\/ads\/|appspot\.com\/stats|ad\.admitad\.com\/banner\/|lovefilm\.com\/partners\/|vodpod\.com\/stats\/|spacash\.com\/popup\/|wired\.com\/event|gamestar\.de\/_misc\/tracking\/|msn\.com\/tracker\/|chameleon\.ad\/banner\/|videowood\.tv\/ads|conduit\.com\/\/banners\/|soundcloud\.com\/event|rapidgator\.net\/images\/pics\/|amazonaws\.com\/fby\/|sawlive\.tv\/ad|livedoor\.com\/counter\/|phncdn\.com\/iframe|sydneyolympicfc\.com\/admin\/media_manager\/media\/mm_magic_display\/|daylogs\.com\/counter\/|twitter\.com\/i\/jot|fulltiltpoker\.com\/affiliates\/|cloudfront\.net\/facebook\/|hosting24\.com\/images\/banners\/|addthis\.com\/live\/|cnn\.com\/ad\-|ad\.atdmt\.com\/i\/img\/|sourceforge\.net\/log\/|quora\.com\/_\/ad\/|static\.criteo\.net\/js\/duplo[^\w.%-]|xhamster\.com\/ads\/|nytimes\.com\/ads\/|shareaholic\.com\/analytics_|sparklit\.com\/counter\/|cafemomstatic\.com\/images\/background\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|facebook\.com\/plugins\/follow|citygridmedia\.com\/ads\/|trustpilot\.com\/stats\/|worldfree4u\.top\/banners\/|ad\.atdmt\.com\/s\/|dailypioneer\.com\/images\/banners\/|secureupload\.eu\/banners\/|google\.com\/log|static\.criteo\.net\/images[^\w.%-]|google\-analytics\.com\/collect|filecrypt\.cc\/p\.|keepvid\.com\/ads\/|liutilities\.com\/partners\/|firedrive\.com\/tools\/|vidzi\.tv\/mp4|linkedin\.com\/img\/|dailymotion\.com\/track\-|dailymotion\.com\/track\/|mochiads\.com\/srv\/|baidu\.com\/billboard\/pushlog\/|girlfriendvideos\.com\/ad|tube18\.sex\/tube18\.|pornmaturetube\.com\/content\/|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|kqzyfj\.com\/image\-|xxvideo\.us\/ad728x15|allmyvideos\.net\/js\/ad_|ad\.admitad\.com\/fbanner\/|trrsf\.com\/metrics\/|youtube\.com\/pagead\/|cdn77\.org\/tags\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|videoplaza\.com\/proxy\/distributor\/|amazon\.com\/clog\/|theporncore\.com\/contents\/content_sources\/|ad\.atdmt\.com\/e\/|virool\.com\/widgets\/|3movs\.com\/contents\/content_sources\/|amazonaws\.com\/publishflow\/|amazonaws\.com\/ownlocal\-|facebook\.com\/plugins\/likebox\/|livefyre\.com\/tracking\/|broadbandgenie\.co\.uk\/widget|hulkload\.com\/b\/|internetbrands\.com\/partners\/|hentaistream\.com\/wp\-includes\/images\/bg\-|ad\.atdmt\.com\/m\/|andyhoppe\.com\/count\/|static\.criteo\.com\/images[^\w.%-]|ncrypt\.in\/images\/a\/|mtvnservices\.com\/metrics\/|softpedia\-static\.com\/images\/aff\/|filedownloader\.net\/design\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|sulia\.com\/papi\/sulia_partner\.js\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|static\.criteo\.com\/flash[^\w.%-]|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|phncdn\.com\/images\/banners\/|tlavideo\.com\/affiliates\/|upsellit\.com\/custom\/|singlehop\.com\/affiliates\/|aliexpress\.com\/js\/beacon_|wishlistproducts\.com\/affiliatetools\/|advfn\.com\/tf_|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|recomendedsite\.com\/addon\/upixel\/|remixshop\.com\/bg\/site\/ajaxCheckCookiePolicy|creativecdn\.com\/pix\/|googleusercontent\.com\/tracker\/|autotrader\.co\.za\/partners\/|bluehost\-cdn\.com\/media\/partner\/images\/|vitalmtb\.com\/assets\/vital\.aba\-|chaturbate\.com\/creative\/|betwaypartners\.com\/affiliate_media\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|apester\.com\/event[^\w.%-]|sitegiant\.my\/affiliate\/|allanalpass\.com\/track\/|dailymotion\.com\/logger\/|foxadd\.com\/addon\/upixel\/|reevoo\.com\/track\/|questionmarket\.com\/static\/|googlesyndication\.com\/simgad\/|youtube\-nocookie\.com\/device_204|cloudfront\.net\/instagram\/|facebook\.com\/plugins\/subscribe|ad\.mo\.doubleclick\.net\/dartproxy\/|akamai\.net\/chartbeat\.|bridgetrack\.com\/site\/|vipbox\.tv\/js\/layer\-|camvideos\.tv\/tpd\.|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|rt\.com\/static\/img\/banners\/|turnsocial\.com\/track\/|femalefirst\.co\.uk\/widgets\/|doubleclick\.net\/N2\/pfadx\/video\.wsj\.com\/|techkeels\.com\/creatives\/|h2porn\.com\/contents\/content_sources\/|bruteforcesocialmedia\.com\/affiliates\/|metromedia\.co\.za\/bannersys\/banners\/|thebull\.com\.au\/admin\/uploads\/banners\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|couptopia\.com\/affiliate\/|theolympian\.com\/static\/images\/weathersponsor\/|bpath\.com\/affiliates\/|adm\.fwmrm\.net\/p\/mtvn_live\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|mrskin\.com\/data\/mrskincash\/|doubleclick\.net\/adx\/wn\.nat\.|carbiz\.in\/affiliates\-and\-partners\/|ibtimes\.com\/banner\/|majorgeeks\.com\/images\/download_sd_|dealextreme\.com\/affiliate_upload\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|beacons\.vessel\-static\.com\/xff|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|bigrock\.in\/affiliate\/|cnzz\.com\/stat\.|goldmoney\.com\/~\/media\/Images\/Banners\/|appinthestore\.com\/click\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|chaturbate\.com\/sitestats\/openwindow\/|bits\.wikimedia\.org\/geoiplookup|getreading\.co\.uk\/static\/img\/bg_takeover_|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|whozacunt\.com\/images\/banner_|mightydeals\.com\/widget|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|browsershots\.org\/static\/images\/creative\/|ad\.doubleclick\.net\/ddm\/trackclk\/|tehrantimes\.com\/banner\/|obox\-design\.com\/affiliate\-banners\/|vivatube\.com\/upload\/banners\/|pussycash\.com\/content\/banners\/|pixazza\.com\/track\/|sysomos\.com\/track\/|luminate\.com\/track\/|picbucks\.com\/track\/|ru4\.com\/click|targetspot\.com\/track\/|dw\.com\/tracking\/|clickandgo\.com\/booking\-form\-widget|theseblogs\.com\/visitScript\/|videos\.com\/click|share\-online\.biz\/affiliate\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|urlcash\.org\/banners\/|media\.domainking\.ng\/media\/|themis\-media\.com\/media\/global\/images\/cskins\/|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|inhumanity\.com\/cdn\/affiliates\/|storage\.to\/affiliate\/|theday\.com\/assets\/images\/sponsorlogos\/|ctctcdn\.com\/js\/signup\-form\-widget\/|ehow\.com\/services\/jslogging\/log\/|brandcdn\.com\/pixel\/|wonderlabs\.com\/affiliate_pro\/banners\/|proxysolutions\.net\/affiliates\/|unblockedpiratebay\.com\/external\/|express\.de\/analytics\/|facebook\.com\/method\/links\.getStats|ppc\-coach\.com\/jamaffiliates\/|drivearchive\.co\.uk\/images\/amazon\.|googlesyndication\.com\/sadbundle\/|ad2links\.com\/js\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|aftonbladet\.se\/blogportal\/view\/statistics|taboola\.com\/tb|media\.complex\.com\/videos\/prerolls\/|regnow\.img\.digitalriver\.com\/vendor\/37587\/ud_box|filez\.cutpaid\.com\/336v|amazonaws\.com\/statics\.reedge\.com\/|pan\.baidu\.com\/api\/analytics|hottubeclips\.com\/stxt\/banners\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|groupon\.com\/tracking|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|axandra\.com\/affiliates\/|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|graduateinjapan\.com\/affiliates\/|punterlink\.co\.uk\/images\/storage\/siteban|bing\.com\/widget\/render\/|itweb\.co\.za\/logos\/|tvducky\.com\/imgs\/graboid\.|worldradio\.ch\/site_media\/banners\/|epictv\.com\/sites\/default\/files\/290x400_|viglink\.com\/api\/batch[^\w.%-]|updatetube\.com\/iframes\/|yyv\.co\/track\/|visa\.com\/logging\/logEvent|jenningsforddirect\.co\.uk\/sitewide\/extras\/|sectools\.org\/shared\/images\/p\/|thrillist\.com\/track|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|twitch\.tv\/track\/|pwpwpoker\.com\/images\/banners\/|aerotime\.aero\/upload\/banner\/|vindicosuite\.com\/tracking\/|channel4\.com\/assets\/programmes\/images\/originals\/|services\.webklipper\.com\/geoip\/|ejpress\.org\/img\/banners\/|vipstatic\.com\/mars\/|appwork\.org\/hoster\/banner_|bwwstatic\.com\/socialtop|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|amarotic\.com\/Banner\/|dota\-trade\.com\/img\/branding_|xscores\.com\/livescore\/banners\/|talkphotography\.co\.uk\/images\/externallogos\/banners\/|debtconsolidationcare\.com\/affiliate\/tracker\/|getadblock\.com\/images\/adblock_banners\/|tsite\.jp\/static\/analytics\/|accuradio\.com\/static\/track\/|nfl\.com\/assets\/images\/hp\-poweredby\-|redditstatic\.com\/moat\/|parliamentlive\.tv\/cookie\/|djmag\.co\.uk\/sites\/default\/files\/takeover\/|chefkoch\.de\/counter|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|adm24\.de\/hp_counter\/|ball2win\.com\/Affiliate\/|flipkart\.com\/ajaxlog\/visitIdlog|ironsquid\.tv\/data\/uploads\/sponsors\/|thelodownny\.com\/leslog\/ads\/|olark\.com\/track\/|cumulus\-cloud\.com\/trackers\/|t5\.ro\/static\/|vpnarea\.com\/affiliate\/|relink\.us\/images\/|shinypics\.com\/blogbanner\/|sacbee\.com\/static\/dealsaver\/|borrowlenses\.com\/affiliate\/|thereadystore\.com\/affiliate\/|drom\.ru\/dummy\.|moneycontrol\.co\.in\/images\/promo\/|adyou\.me\/bug\/adcash|amazon\.com\/gp\/yourstore\/recs\/|totallylayouts\.com\/online\-users\-counter\/|cloudfront\.net\/linkedin\/|nudography\.com\/photos\/banners\/|homoactive\.tv\/banner\/|go\.com\/stat\/|ziffstatic\.com\/jst\/zdvtools\.|nmap\.org\/shared\/images\/p\/|lumfile\.com\/lumimage\/ourbanner\/|seclists\.org\/shared\/images\/p\/|amazonaws\.com\/btrb\-prd\-banners\/|brettterpstra\.com\/wp\-content\/uploads\/|inquirer\.net\/wp\-content\/themes\/news\/images\/wallpaper_|americanfreepress\.net\/assets\/images\/Banner_|golem\.de\/staticrl\/scripts\/golem_cpxl_|dailymail\.co\.uk\/tracking\/|aebn\.net\/banners\/|1320wils\.com\/assets\/images\/promo%20banner\/|createtv\.com\/CreateProgram\.nsf\/vShowcaseFeaturedSideContentByLinkTitle\/|knco\.com\/wp\-content\/uploads\/wpt\/|mixpanel\.com\/track|vindicosuite\.com\/track\/|download\.bitdefender\.com\/resources\/media\/|static\.multiplayuk\.com\/images\/w\/w\-|a\.huluad\.com\/beacons\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|facebook\.com\/friends\/requests\/log_impressions|go2cdn\.org\/brand\/|c21media\.net\/wp\-content\/plugins\/sam\-images\/|googlesyndication\.com\/ddm\/|spiceworks\.com\/share\/|zanox\-affiliate\.de\/ppv\/|imdb\.com\/tr\/|avira\.com\/site\/datatracking|watchuseek\.com\/media\/1900x220_|sextvx\.com\/static\/images\/tpd\-|videowood\.tv\/pop2|amazonaws\.com\/new\.cetrk\.com\/|draugiem\.lv\/lapas\/widgets\/|toolslib\.net\/assets\/img\/a_dvt\/|rbth\.ru\/widget\/|twitter\.com\/abacus|text\-compare\.com\/media\/global_vision_banner_|video\.mediaset\.it\/polymediashowanalytics\/|betterbills\.com\.au\/widgets\/|ask\.com\/servlets\/ulog|purevpn\.com\/affiliates\/|nation\.sc\/images\/banners\/|safarinow\.com\/affiliate\-zone\/|metroweekly\.com\/tools\/blog_add_visitor\/|freemoviestream\.xyz\/wp\-content\/uploads\/|dx\.com\/affiliate\/|premiumtradings\.com\/media\/images\/index_banners\/|smn\-news\.com\/images\/banners\/|apple\.com\/itunesaffiliates\/|s3\.amazonaws\.com\/draftset\/banners\/|lgoat\.com\/cdn\/amz_|ziffstatic\.com\/jst\/zdsticky\.|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|tshirthell\.com\/img\/affiliate_section\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|yea\.xxx\/img\/creatives\/|wykop\.pl\/dataprovider\/diggerwidget\/|babyblog\.ru\/pixel|russian\-dreams\.net\/static\/js\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|plugins\.longtailvideo\.com\/yourlytics|cdn\.69games\.xxx\/common\/images\/friends\/|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|any\.gs\/visitScript\/|djmag\.com\/sites\/default\/files\/takeover\/|110\.45\.173\.103\/ad\/|amazonaws\.com\/streetpulse\/ads\/|getnzb\.com\/img\/partner\/banners\/|camwhores\.tv\/contents\/other\/player\/|oodle\.co\.uk\/event\/track\-first\-view\/|jobs\-affiliates\.ws\/images\/|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|hardsextube\.com\/preroll\/getiton\/|fairfaxregional\.com\.au\/proxy\/commercial\-partner\-solar\/|mcvuk\.com\/static\/banners\/|gadget\.co\.za\/siteimages\/banners\/|nutritionhorizon\.com\/content\/banners\/|preisvergleich\.de\/setcookie\/|adsl2exchanges\.com\.au\/images\/spintel|uploading\.com\/static\/banners\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|graboid\.com\/affiliates\/|doubleclick\.net\/N6872\/pfadx\/shaw\.mylifetimetv\.ca\/|nigeriafootball\.com\/img\/affiliate_|iradio\.ie\/assets\/img\/backgrounds\/|videos\.mediaite\.com\/decor\/live\/white_alpha_60\.|twitter\.com\/scribes\/|hostdime\.com\/images\/affiliate\/|attn\.com\/survey|usps\.com\/survey\/|dreamstime\.com\/refbanner\-|virtualhottie2\.com\/cash\/tools\/banners\/|yimg\.com\/uq\/syndication\/|presscoders\.com\/wp\-content\/uploads\/misc\/aff\/|govevents\.com\/display\-file\/|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|citeulike\.org\/static\/campaigns\/|geometria\.tv\/banners\/|suite101\.com\/tracking\/|digitalsatellite\.tv\/banners\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|customerlobby\.com\/ctrack\-|tourradar\.com\/def\/partner|foxtel\.com\.au\/cms\/fragments\/corp_analytics\/|vator\.tv\/tracking\/|putpat\.tv\/tracking|oasap\.com\/images\/affiliate\/|videovalis\.tv\/tracking\/|nijobfinder\.co\.uk\/affiliates\/|desperateseller\.co\.uk\/affiliates\/|timesinternet\.in\/ad\/|moneywise\.co\.uk\/affiliate\/|doubleclick\.net\/json|porn2blog\.com\/wp\-content\/banners\/|vigilante\.pw\/img\/partners\/)/i;
var bad_da_hostpath_regex_flag = 499 > 0 ? true : false;  // test for non-zero number of rules
    
// 212 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|erotikdeal\.com\/\?ref=|banner\.|affiliates\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banners\.|synad\.|quantserve\.com\/pixel;|affiliate\.|cloudfront\.net\/\?a=|ad\.atdmt\.com\/i\/go;|api\-read\.facebook\.com\/restserver\.php\?api_key=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|graph\.facebook\.com\/fql\?q=SELECT|oddschecker\.com\/clickout\.htm\?type=takeover\-|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|movies\.askjolene\.com\/c64\?clickid=|cloudfront\.net\/\?tid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|yahoo\.com\/p\.gif;|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|sweed\.to\/\?pid=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |amazonaws\.com\/\?wsid=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|gawker\.com\/\?op=hyperion_useragent_data|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yifyddl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|watchfree\.to\/download\.php\?type=1&title=|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|videobox\.com\/\?tid=|mail\.yahoo\.com\/neo\/mbimg\?av\/curveball\/ds\/|totalporn\.com\/videos\/tracking\/\?url=|x1337x\.se[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|affiliates2\.|977music\.com\/index\.php\?p=get_loading_banner|plista\.com\/async\/min\/video,outstream\/|google\.com\/uds\/\?file=orkut&|irs01\.|1337x\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|elb\.amazonaws\.com\/\?page=|777livecams\.com\/\?id=|eurolive\.com\/index\.php\?module=public_eurolive_onlinetool&|inn\.co\.il\/Controls\/HPJS\.ashx\?act=log|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|eurolive\.com\/\?module=public_eurolive_onlinehostess&|ooyala\.com\/authorized\?analytics|yahoo\.com\/serv\?s|ab\-in\-den\-urlaub\.de\/resources\/cjs\/\?f=\/resources\/cjs\/tracking\/|oneload\.site[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yahoo\.com\/yi\?bv=|google\.com\/_\/\+1\/|x1337x\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|jewsnews\.co\.il[^\w.%-]\$csp=script\-src 'self' |247hd\.net\/ad$|monova\.org[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|comicgenesis\.com\/tcontent\.php\?out=|plista\.com\/jsmodule\/flash$|seedpeer\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|gameknot\.com\/amaster\.pl\?j=|rehost\.to\/\?ref=|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\1|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\2|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\3|allmyvideos\.net\/(?=([\s\S]*?=))\4|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\5|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\6|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\7|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\8|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\9|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\10(?=([\s\S]*?\.gstatic\.com ))\11(?=([\s\S]*?\.google\.com ))\12(?=([\s\S]*?\.googleapis\.com))\13|thevideo\.me\/(?=([\s\S]*?\:))\14|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\15|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\16|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\17|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\18|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\19|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\20|doubleclick\.net[^\w.%-](?=([\s\S]*?;afv_flvurl=http\:\/\/cdn\.c\.ooyala\.com\/))\21|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\22|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\23|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\24|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\25|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\26|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\27|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\28|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\29(?=([\s\S]*?=))\30|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\31|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\32|trove\.com[^\w.%-](?=([\s\S]*?&uid=))\33|videolike\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\34|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\35(?=([\s\S]*?&s=))\36(?=([\s\S]*?&h=))\37|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\38|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\39|facebook\.com\/restserver\.php\?(?=([\s\S]*?\.getStats&))\40|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\41|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\42(?=([\s\S]*?&offer_id=))\43|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\44|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\45|facebook\.com\/connect\/connect\.php\?(?=([\s\S]*?width))\46(?=([\s\S]*?&height))\47|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\48|readcomiconline\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.disquscdn\.com ))\49(?=([\s\S]*?\.disqus\.com))\50|tipico\.(?=([\s\S]*?\?affiliateId=))\51|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\52|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\53|l\.yimg\.com[^\w.%-](?=([\s\S]*?&partner=))\54(?=([\s\S]*?&url=))\55|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\56|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\57|zabasearch\.com\/search_box\.php\?(?=([\s\S]*?&adword=))\58|plarium\.com\/play\/(?=([\s\S]*?adCampaign=))\59|convertcase\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\60|gogoanimes\.co[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? disquscdn\.com 'unsafe\-inline'))\61|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\62|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\63|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\64|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\65|twitter\.com\/i\/cards\/tfw\/(?=([\s\S]*?\?advertiser_name=))\66|media\.campartner\.com[^\w.%-](?=([\s\S]*?\?cp=))\67|ebayobjects\.com\/(?=([\s\S]*?;dc_pixel_url=))\68|freean\.us[^\w.%-](?=([\s\S]*?\?ref=))\69|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\70|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\71|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\72|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\73|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\74|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\75|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\76|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\77|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\78|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\79|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\80|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\81|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\82|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\83|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\84|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\85|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\86|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\87|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\88|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\89|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\90|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\91|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\92|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\93|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\94|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\95|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\96|yimg\.com[^\w.%-](?=([\s\S]*?\/l\?ig=))\97|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\98|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\99|yahoo\.(?=([\s\S]*?\/serv\?s=))\100|newser\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\101|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\102|assoc\-amazon\.(?=([\s\S]*?[^\w.%-]e\/ir\?t=))\103|bittorrentstart\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' data\: (?=([\s\S]*?\.google\.com ))\104(?=([\s\S]*?\.google\-analytics\.com ))\105(?=([\s\S]*?\.scorecardresearch\.com))\106|daclips\.in[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\107|lolcounter\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\108|nsfwyoutube\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\109|unlockproject\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\110|mrunlock\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\111|tamilo\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\112|datpiff\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\113|allthetests\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\114|hiphoplately\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\115|breakingisraelnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\116|mjtlive\.com\/exports\/golive\/\?lp=(?=([\s\S]*?&afno=))\117|r\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/rtd\?ptid))\118|unblocked\.app[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\119|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\120|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/webyp\?rid=))\121|static\.hd\-trailers\.net\/js\/javascript_(?=([\s\S]*?\.js$))\122|cyberprotection\.pro[^\w.%-](?=([\s\S]*?\?aff))\123|google\.(?=([\s\S]*?\/stats\?frame=))\124|phonesreview\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\125|unblocked\.si[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\126|torrentz\.eu\/search(?=([\s\S]*?=))\127|shopify\.com\/(?=([\s\S]*?\/page\?))\128(?=([\s\S]*?&eventType=))\129|unblocked\.llc[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\130|nocensor\.pro[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\131|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\132|filefactory\.com[^\w.%-](?=([\s\S]*?\/refer\.php\?hash=))\133|netflix\.com\/beacons\?(?=([\s\S]*?&ssizeCat=))\134(?=([\s\S]*?&vsizeCat=))\135|unblocked\.lol[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\136|solarmoviez\.ru[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\137|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\138|downloadprovider\.me\/en\/search\/(?=([\s\S]*?\?aff\.id=))\139(?=([\s\S]*?&iframe=))\140|clickbank\.net\/(?=([\s\S]*?offer_id=))\141|amazonaws\.com\/betpawa\-(?=([\s\S]*?\.html\?aff=))\142|huluim\.com\/(?=([\s\S]*?&beaconevent))\143|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\144|deals4thecure\.com\/widgets\/(?=([\s\S]*?\?affiliateurl=))\145|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\146|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?&ptid))\147|c\.ypcdn\.com[^\w.%-](?=([\s\S]*?\?ptid))\148|events\.eyeviewdigital\.com[^\w.%-](?=([\s\S]*?\.gif\?r=))\149|cloudfront\.net(?=([\s\S]*?\/sp\.js$))\150|bitcoinist\.net\/wp\-content\/(?=([\s\S]*?\/g\+\.png))\151|onhax\.me[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\152)/i;
var bad_da_regex_flag = 212 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 499 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/img\/tumblr\-|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\/social\-media\.|\/social_media\/|\/expandable_ad\?|\/img\/adv\.|\/img\/adv\/|\/homepage\-ads\/|\/homepage\/ads\/|\/ad_pop\.php\?|\/ad\-engine\.|\/ad_engine\?|\-web\-ad\-|\/web\-ad_|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\-online\-advert\.|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\/eu_cookies\.|\/online\-ad_|_online_ad\.|\.com\/video\-ad\-|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.cookie_law\.|\/cookie_law\/|\/static\/tracking\/|_js\/ads\.js|\/cookie\-information\.|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/cookiecompliance\.|=adcenter&|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|\/superads_|\/eu\-cookie\.|\/eu\-cookie\/|_eu_cookie\.|_eu_cookie_|\/t\/event\.js\?|\/web\-analytics\.|\/web_analytics\/|\.com\/\?adv=|\/popad$|\/cookie\-consent\.|\/cookie\-consent\/|\/cookie\-consent\?|\/cookie_consent\.|\/cookie_consent\/|\/cookie_consent_|_cookie_consent\/|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\-CookieInfo\.|\/CookieInfo\.|\.adriver\.|\/adriver\.|\/adriver_|\/ad\.php$|\/pop2\.js$|\/bottom\-ads\.|\/expandable_ad\.php|_search\/ads\.js|\/ad132m\/|\/post\/ads\/|\/bg\/ads\/|\/xtclicks\.|\/xtclicks_|\.cookienotice\.|\/cookienotice\-|\/cookienotice\.|\/footer\-ads\/|\/adclick\.|\-show\-ads\.|\/show\-ads\.|\-top\-ads\.|\/top\-ads\.|\-text\-ads\.|\/media\/ad\/|\/afs\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\/twittericon\.|\/facebookicon\.|\/mobile\-ads\/|\.co\/ads\/|\/dynamic\/ads\/|\/special\-ads\/|\/socialmedia_|\/user\/ads\?|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/pc\/ads\.|\/cms\/ads\/|\/modules\/ads\/|\/ads\.cms|\/ads\/html\/|\/showads\/|\/ad\?count=|\/ad_count\.|\/i\/ads\/|\/player\/ads\.|\/player\/ads\/|\.no\/ads\/|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/ext\/ads\/|\/custom\/ads|\/vast\/ads\-|\/default\/ads\/|\/mini\-ads\/|\/external\/ads\/|\/left\-ads\.|\/delivery\.ads\.|\/ad\/logo\/|\/responsive\-ads\.|\/sidebar\-ads\/|&program=revshare&|_track\/ad\/|\/inc\/ads\/|\/jssocials\-|\/jssocials_|\/remove\-ads\.|\.net\/ad\/|\/house\-ads\/|\/ads12\.|\/ads\/async\/|\-adskin\.|\/adskin\/|\/ad\?sponsor=|\/ads\/click\?|\/adsetup\.|\/adsetup_|\/adsframe\.|\/td\-ads\-|\/adsdaq_|\/click\?adv=|\/social\-likes\-|\/adbanners\/|\/blogad\.|\/analytics\.gif\?|\/popupads\.|\/ads\.htm|\/ads\/targeting\.|\/adv\-socialbar\-|\/click\.track\?|\/adsrv\.|\/adsrv\/|\/ads_reporting\/|\.ads\.css|\/ads\.css|\.online\/ads\/|\/online\/ads\/|\/image\/ads\/|\/image\/ads_|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\-peel\-ads\-|\.com\/js\/ads\/|\/adlog\.|\/adsys\.|&adcount=|\/aff_ad\?|\/partner\.ads\.|\.link\/ads\/|\/social\-media\-banner\.|\/ads\.php|\/ads_php\/|\/ads\/square\-|\/ads\/square\.|\/plugins\/ads\-|\/plugins\/ads\/|\/log\/ad\-|\/log_ad\?|\/sharebar\.|\-sharebar\-|\-sharebar\.|\/sponsored_ad\.|\/sponsored_ad\/|\/realmedia\/ads\/|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/video\-ad\-overlay\.|\/new\-ads\/|\/new\/ads\/|\/adstop\.|\/adstop_|\-adsonar\.|\/adsonar\.|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/adpartner\.|\?adpartner=|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|=popunders&|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\/bin\/stats\?|\/icon\/share\-|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|\/lazy\-ads\-|\/lazy\-ads\.|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\/blog\/ads\/|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/adClick\/|\/adClick\?|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\.ads9\.|\/ads9\.|\/ads9\/|\-adsystem\-|\/adsystem\.|\/adsystem\/|\.ads3\-|\/ads3\.|\/ads3\/|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/bannerad\.|\/bannerad\/|_bannerad\.|\/s_ad\.aspx\?|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\/google\/adv\.|\/ads\/text\/|\/ads_text_|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\/img\/social\/|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\/pages\/ads|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/google_tag\.|\/google_tag\/|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\/adstat\.|\-social\-share\/|\-social\-share_|\.social\/share\/|\/social\-share\-|\/social\/share\-|\/social\/share_|\/social_share_|_social_share_|\.net\/adx\.php\?|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\/sharetools\/|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\/images\/social_|\/admanager\/|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\/assets\/twitter\-|\/assets\/js\/ad\.|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/ad\/js\/pushdown\.|&adserver=|\-adserver\-|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/images\/gplus\-|\/media\/ads\/|_media\/ads\/|\/img\/gplus_|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/a\-ads\.|\.com\/counter\?|\/static\/ads\/|_static\/ads\/|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\/2\/ads\/|\/head\-social\.|\/assets\/facebook\-|\/1\/ads\/|_mobile\/js\/ad\.|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\/wp\-content\/plugins\/automatic\-social\-locker\/|\-social\-media\.|\/social_media_|_social\-media_|\/tracker\/tracker\.js|\/img\/rss\.|\/img\/rss_|\/videoad\.|_videoad\.|\.sharecounter\.|&advertiserid=|\/cookie\-law\.js|\/cookie_law\.js|_cookie_law\.js|\/adworks\/|\/adwords\/|\/userad\/|_mainad\.|\/admax\/|_WebAd[^\w.%-]|\/product\-ad\/|\/social_bookmarking\/|\-ad0\.|\-social\-linked\-|_social_linked_|=advertiser\.|=advertiser\/|\?advertiser=|\/googlead\-|\/googlead\.|_googlead\.|\/adlink\?|\/adlink_|\/ad\-minister\-|\/cookies\-monster\.js|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\-adops\.|\/adops\/|\-google\-ads\-|\-google\-ads\/)/i;
var bad_url_parts_flag = 499 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_RegExp = /^$/;
var good_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_url_RegExp = /^$/;
var bad_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0",
"172.16.0.0,        255.240.0.0",
"192.168.0.0,       255.255.0.0",
"127.0.0.0,         255.0.0.0",
"17.0.0.0,          255.0.0.0",
"23.2.8.68,         255.255.255.255",
"23.2.145.78,       255.255.255.255",
"23.39.179.17,      255.255.255.255",
"23.63.98.0,        255.255.254.0",
"104.70.71.223,     255.255.255.255",
"104.73.77.224,     255.255.255.255",
"104.96.184.235,    255.255.255.255",
"104.96.188.194,    255.255.255.255",
"65.52.0.0,         255.255.252.0" ];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [ "17.172.28.11,     255.255.255.255",
"134.170.30.202,    255.255.255.255",
"137.116.81.24,     255.255.255.255",
"157.56.106.189,    255.255.255.255",
"184.86.53.99,      255.255.255.255",
"2.22.61.43,        255.255.255.255",
"2.22.61.66,        255.255.255.255",
"204.79.197.200,    255.255.255.255",
"23.218.212.69,     255.255.255.255",
"65.39.117.230,     255.255.255.255",
"65.52.108.33,      255.255.255.255",
"65.55.108.23,      255.255.255.255",
"64.4.54.254,       255.255.255.255" ];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [ "61.139.105.128,    255.255.255.192",
"63.140.35.160,  255.255.255.248",
"63.140.35.168,  255.255.255.252",
"63.140.35.172,  255.255.255.254",
"63.140.35.174,  255.255.255.255",
"66.150.161.32,  255.255.255.224",
"66.235.138.0,   255.255.254.0",
"66.235.141.0,   255.255.255.0",
"66.235.143.48,  255.255.255.254",
"66.235.143.64,  255.255.255.254",
"66.235.153.16,  255.255.255.240",
"66.235.153.32,  255.255.255.248",
"81.31.38.0,     255.255.255.128",
"82.98.86.0,     255.255.255.0",
"89.185.224.0,   255.255.224.0",
"207.66.128.0,   255.255.128.0" ];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]*)(\\??\\S*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24})\\.?", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;

    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-internals/#events
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

// EasyList filtering for FindProxyForURL(url, host)
function EasyListFindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;

    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;

    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////

    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////

        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return proxy;
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [firefox]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////

    if (scheme == "https" || scheme == "http") {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return proxy;
}

// User-supplied FindProxyForURL()
function FindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,4) == "ftp:")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}   
