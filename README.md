burp-plugin-requestutils
========================

A plugin for manipulating and converting HTTP requests in PortSwigger Burp Suite Pro v1.5+

Current Features:
  * Convert request to equivalent code/command
    * cURL
  * Reduce request params/headers to minimum required to get same response
  
Planned Features:
  * Convert request to equivalent code/command
    * Wget
    * Powershell (Invoke-RestMethod/Invoke-WebRequest)
    * .NET WebRequest 
    * Java HttpURLConnection
    * Ruby net/http
    * Python urllib2    
  * Make reduce request functionality suck less
