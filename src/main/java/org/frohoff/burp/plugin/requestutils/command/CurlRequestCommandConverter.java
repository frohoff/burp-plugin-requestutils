package org.frohoff.burp.plugin.requestutils.command;

import static org.frohoff.burp.plugin.requestutils.StringUtils.escapeQuotes;

import java.net.URL;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.frohoff.burp.plugin.requestutils.StringUtils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class CurlRequestCommandConverter implements RequestCommandConverter {
	@Override
	public String toCommand(IHttpRequestResponse message, IRequestInfo req) {
		URL url = message.getUrl();
		List<String> comm = new LinkedList<String>();
		comm.add("curl");
		comm.add("'" + escapeQuotes(url.toString()) + "'");
		if (!"GET".equals(req.getMethod()) && !"POST".equals(req.getMethod())) { // set method
			comm.add(formatFlag("-X", req.getMethod()));	
		}		
		for (String header : req.getHeaders()) { // add headers
			System.out.println("Header: '" + header + "'");
			// TODO: fallback to -H for weird cookie headers
			if (header.startsWith("Cookie:")) {
				String[] cookieParts = header.split("\\s*:\\s*", 2);
				comm.add(formatFlag("-b", cookieParts[1]));
			} else if (header.startsWith("Host:")) {
				String[] hostParts = header.split("\\s*:\\s*", 2);
				if (! hostParts[1].equals(message.getHttpService().getHost())) { // only add if different from host in URL
					comm.add(formatFlag("-H", header));					
				}
			} else if (! header.startsWith(req.getMethod()) && ! header.startsWith("Content-Length:")) {				
				comm.add(formatFlag("-H", header));
			}
		}
		if ("POST".equals(req.getMethod()) || "PUT".equals(req.getMethod())) { // add POST/PUT payload
			byte[] reqBytes = message.getRequest();
			String body = new String(Arrays.copyOfRange(reqBytes, req.getBodyOffset(), reqBytes.length));			
			comm.add(formatFlag("-d", body));
		}
		comm.add("--compress"); // automatically decompress compressed responses
		return StringUtils.join(comm, " ");
	}
	
	protected String formatFlag(String flag, String value) {
		return flag + (value != null ? " '" + escapeQuotes(value) + "'" : "");
	}

	@Override
	public String getName() {
		return "cURL";
	}
}