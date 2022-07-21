function FindProxyForURL(url, host)
{

   /* Normalize the URL for pattern matching */
   url = url.toLowerCase();
   host = host.toLowerCase();






   var hostOrDomainIs = function(host, val) {
      return (host === val) || dnsDomainIs(host, '.' + val);
   };

   var hostIs = function(host, val) {
      return (host === val);
   };

   /* Don't proxy local hostnames */
   if (isPlainHostName(host))
   {
      return 'DIRECT';
   }



    /* Don't check IPv6 addresses */
   if (isResolvable(host))
   {
      var hostIP = dnsResolve(host);
      if (!shExpMatch(hostIP, "*:*"))
      {
        /* Don't proxy non-routable addresses (RFC 3330) */
        if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
        isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
        isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
        isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
        isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
        isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
        isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
        isInNet(hostIP, '240.0.0.0', '240.0.0.0'))
        {
           return 'DIRECT';
        }
      }
   }






   /* All other service traffic goes through proxy */
   if ( dnsDomainIs(host, "devatron.net") )
   {
      return 'PROXY safeview-8ssa75649-quangnguyen.devatron.net:3129; DIRECT';
   }



   /* List all default domains */

   if ( shExpMatch(host, "google.??") ||
	shExpMatch(host, "google.com") ||
	shExpMatch(host, "google.com.??") ||
	shExpMatch(host, "google.co.??") ||
	shExpMatch(host, "*.google.??") ||
	shExpMatch(host, "*.google.com") ||
	shExpMatch(host, "*.google.com.??") ||
	shExpMatch(host, "*.google.co.??"))
   {
      return 'DIRECT';
   }
   
   if ( dnsDomainIs(host, ".windowsupdate.microsoft.com") ||
	dnsDomainIs(host, ".update.microsoft.com") ||
	dnsDomainIs(host, ".download.microsoft.com") ||
	dnsDomainIs(host, ".ntservicepack.microsoft.com") ||
	dnsDomainIs(host, ".cdm.microsoft.com") ||
	dnsDomainIs(host, ".wustat.windows.com") ||
	dnsDomainIs(host, "store-images.s-microsoft.com") ||
	dnsDomainIs(host, "musicimage.xboxlive.com") ||
	dnsDomainIs(host, "store-images.microsoft.com") ||
	dnsDomainIs(host, "mediadiscovery.microsoft.com") ||
	dnsDomainIs(host, "media-assetcatalog.microsoft.com") ||
	dnsDomainIs(host, "mp.microsoft.com") ||
	dnsDomainIs(host, "sls.microsoft.com"))
   {
      return 'DIRECT';
   }
   
   if ( dnsDomainIs(host, "itunes.apple.com") ||
	dnsDomainIs(host, ".swcdn.apple.com") ||
	dnsDomainIs(host, ".swdownload.apple.com") ||
	dnsDomainIs(host, ".swquery.apple.com") ||
	dnsDomainIs(host, "swscan.apple.com") ||
	dnsDomainIs(host, "xp.apple.com") ||
	dnsDomainIs(host, "gsa.apple.com") ||
	dnsDomainIs(host, "smoot.apple.com") ||
	dnsDomainIs(host, "ls.apple.com") ||
	dnsDomainIs(host, "configuration.apple.com") ||
	dnsDomainIs(host, "gc.apple.com") ||
	dnsDomainIs(host, "ess.apple.com") ||
	dnsDomainIs(host, "gsas.apple.com") ||
	dnsDomainIs(host, "identity.apple.com") ||
	dnsDomainIs(host, "smp-device-content.apple.com") ||
	dnsDomainIs(host, "swdist.apple.com") ||
	dnsDomainIs(host, "mzstatic.com") ||
	hostOrDomainIs(host, "icloud.com") ||
	hostOrDomainIs(host, "api.apps.apple.com"))
   {
      return 'DIRECT';
   }
   
   if ( dnsDomainIs(host, "aus4.mozilla.org") ||
	dnsDomainIs(host, "aus5.mozilla.org") ||
	dnsDomainIs(host, "download.mozilla.org") ||
	dnsDomainIs(host, "download.cdn.mozilla.net") ||
	dnsDomainIs(host, "self-repair.mozilla.org"))
   {
      return 'DIRECT';
   }
   
   if ( dnsDomainIs(host, ".webex.com") ||
	dnsDomainIs(host, ".ciscowebex.com") ||
	hostOrDomainIs(host, "gotomeeting.com") ||
	hostOrDomainIs(host, "gotowebinar.com") ||
	hostOrDomainIs(host, "gototraining.com") ||
	hostOrDomainIs(host, "gotomypc.com") ||
	hostOrDomainIs(host, "gotoassist.com") ||
	hostOrDomainIs(host, "skype.com") ||
	hostOrDomainIs(host, "freeconferencecall.com") ||
	hostOrDomainIs(host, "join.me") ||
	hostOrDomainIs(host, "anymeeting.com") ||
	hostOrDomainIs(host, "clickwebinar.com") ||
	hostOrDomainIs(host, "readytalk.com") ||
	hostOrDomainIs(host, "omnovia.com") ||
	hostOrDomainIs(host, "safeview-8ssa75649-quangnguyen.devatron.net") ||
	hostOrDomainIs(host, "pnr-webui-test-8ssa75649-quangnguyen.devatron.net") ||
	hostOrDomainIs(host, "on24.com"))
   {
      return 'DIRECT';
   }
   
   if ( hostOrDomainIs(host, "netflix.com") ||
	hostOrDomainIs(host, "netflix.net") ||
	hostOrDomainIs(host, "nflximg.com") ||
	hostOrDomainIs(host, "nflximg.net") ||
	hostOrDomainIs(host, "nflxvideo.net") ||
	hostOrDomainIs(host, "nflxext.com") ||
	hostOrDomainIs(host, "nflximg.com.edgesuite.net") ||
	isInNet(host, "216.21.170.128","255.255.255.240") ||
	isInNet(host, "192.173.64.0","255.255.192.0") ||
	isInNet(host, "198.45.48.0","255.255.240.0") ||
	isInNet(host, "216.21.170.96","255.255.255.240") ||
	isInNet(host, "108.175.32.0","255.255.240.0") ||
	isInNet(host, "198.38.96.0","255.255.224.0") ||
	isInNet(host, "192.119.16.224","255.255.255.240") ||
	isInNet(host, "216.21.170.144","255.255.255.240") ||
	isInNet(host, "23.246.0.0","255.255.192.0") ||
	isInNet(host, "37.77.184.0","255.255.255.0") ||
	isInNet(host, "37.77.185.0","255.255.255.0") ||
	isInNet(host, "37.77.188.0","255.255.255.0") ||
	isInNet(host, "37.77.189.0","255.255.255.0") ||
	isInNet(host, "37.77.190.0","255.255.255.0") ||
	isInNet(host, "37.77.191.0","255.255.255.0") ||
	isInNet(host, "69.53.229.0","255.255.255.0") ||
	isInNet(host, "185.2.220.0","255.255.255.0") ||
	isInNet(host, "185.2.221.0","255.255.255.0") ||
	isInNet(host, "185.2.222.0","255.255.255.0") ||
	isInNet(host, "185.2.223.0","255.255.255.0") ||
	isInNet(host, "185.9.188.0","255.255.255.0") ||
	isInNet(host, "192.173.80.0","255.255.192.0") ||
	isInNet(host, "192.173.96.0","255.255.192.0"))
   {
      return 'DIRECT';
   }
   
   if ( hostOrDomainIs(host, "lululemon.com") ||
	hostOrDomainIs(host, "ticketmaster.com") ||
	hostOrDomainIs(host, "ticketmaster.co.uk") ||
	hostOrDomainIs(host, "wayfair.com"))
   {
      return 'DIRECT';
   }
   


   if ( hostOrDomainIs(host, "30000712-menlotest.com"))
   {
      return 'DIRECT';
   }




   if ( url.substring(0, 6) === 'https:' )
   {
      return 'PROXY safeview-8ssa75649-quangnguyen.devatron.net:3129; DIRECT';
   }


   if ( url.substring(0, 5) === 'http:' )
   {
      return 'PROXY safeview-8ssa75649-quangnguyen.devatron.net:3129; DIRECT';
   }

   return 'DIRECT';
}
