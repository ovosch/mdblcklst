function FindProxyForURL(url, host) {
 // Bypass the proxy for *.thewindowsclub.com
 if (dnsDomainIs(host, ".imginn.com")) {
               return "PROXY http://127.0.0.1:18080";
 }
 return "DIRECT";
 } // End of function
