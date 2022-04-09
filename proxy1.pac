var DIRECT = "DIRECT";
var PROXY = "PROXY 127.0.0.1:8119";

var blacklist = [
"delfi.lv",
"inbox.lv",
"tiktok.com",
"offers.intercasino.com",
];

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  for(var i = 0; i < blacklist.length; i++){
    var entry = blacklist[i];
    if(dnsDomainIs(host, entry) || shExpMatch(host, "*." + entry)){
      return PROXY;
    }
  }
  return DIRECT;
}
