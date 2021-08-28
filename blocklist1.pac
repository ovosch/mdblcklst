// Calomel.org Proxy Auto-Config
//

//
// Define the network paths (direct, proxy and deny)
//

// Default connection
var direct = "DIRECT";

// Alternate Proxy Server
var proxy = "PROXY 192.168.1.100:8080";

// Default localhost for denied connections
var deny = "PROXY 127.0.0.1:65535";

//
// Proxy Logic
//

function FindProxyForURL(url, host)
{

// Use Proxy?
if (dnsDomainIs(host, ".domain.home")
  || dnsDomainIs(host, ".whatsmyip.org"))
  { return proxy; }

// Anti-ads and Anti-porn
if (dnsDomainIs(host, ".doubleclick.com")
  || dnsDomainIs(host, ".doubleclick.net")
  || dnsDomainIs(host, ".googlesyndication.com")
  || dnsDomainIs(host, ".delfi.lv")
  || dnsDomainIs(host, ".tjournal.ru")
  || dnsDomainIs(host, ".dumpor.com")
  || dnsDomainIs(host, ".offshoreclicks.com"))
  { return deny; }
 else
  { return direct; }

// Default DENY
{ return deny; }

}
