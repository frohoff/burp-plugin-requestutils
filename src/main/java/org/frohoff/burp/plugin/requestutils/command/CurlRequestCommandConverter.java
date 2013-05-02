package org.frohoff.burp.plugin.requestutils.command;

import java.net.URL;
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
		if (!"GET".equals(req.getMethod()) && !"POST".equals(req.getMethod())) {
			comm.add("-X " + req.getMethod());
		}
		for (String header : req.getHeaders()) {
			System.out.println("Header: '" + header + "'");
			if (! header.startsWith(req.getMethod()) && ! header.startsWith("Host:")) {
				comm.add("-H '" + header + "'");
			}
		}
		return RequestUtilsBurpExtender.join(comm, " ");
	}

	@Override
	public String getName() {
		return "curl";
	}
}