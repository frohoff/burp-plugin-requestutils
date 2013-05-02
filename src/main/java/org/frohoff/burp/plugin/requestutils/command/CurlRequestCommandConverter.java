package org.frohoff.burp.plugin.requestutils.command;

import java.net.URL;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.frohoff.burp.plugin.requestutils.RequestUtilsBurpExtender;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class CurlRequestCommandConverter implements RequestCommandConverter {
	@Override
	public String toCommand(IHttpRequestResponse message, IRequestInfo req) {
		URL url = message.getUrl();
		List<String> comm = new LinkedList<String>();
		comm.add("curl");
		comm.add(url.toString());
		if (!"GET".equals(req.getMethod()) && !"POST".equals(req.getMethod())) { // set method
			comm.add("-X " + req.getMethod());
		}
		for (String header : req.getHeaders()) { // add headers
			System.out.println("Header: '" + header + "'");
			if (! header.startsWith(req.getMethod()) && ! header.startsWith("Host:") && ! header.startsWith("Content-Length:")) {
				comm.add("-H '" + header + "'");
			}
		}
		if ("POST".equals(req.getMethod()) || "PUT".equals(req.getMethod())) { // add POST/PUT payload
			byte[] reqBytes = message.getRequest();
			String body = new String(Arrays.copyOfRange(reqBytes, req.getBodyOffset(), reqBytes.length));			
			comm.add("-d '" + body + "'");
		}
		comm.add("--compress"); // automatically decrompress compressed encodings
		return RequestUtilsBurpExtender.join(comm, " ");
	}

	@Override
	public String getName() {
		return "cURL";
	}
}