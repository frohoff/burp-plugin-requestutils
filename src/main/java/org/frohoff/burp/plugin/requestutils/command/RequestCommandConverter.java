package org.frohoff.burp.plugin.requestutils.command;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public interface RequestCommandConverter {
	public String toCommand(IHttpRequestResponse http, IRequestInfo req);
	public String getName();
}