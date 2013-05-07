package org.frohoff.burp.plugin.requestutils;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.LinkedList;
import java.util.List;

import javax.swing.AbstractAction;

import org.frohoff.burp.plugin.requestutils.command.RequestCommandConverter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class ConvertRequestAction extends AbstractAction {
	private Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();	
	
	private static final long serialVersionUID = -1305935558053936713L;
	private final IBurpExtenderCallbacks callbacks;
	private final IHttpRequestResponse[] https;
	private final RequestCommandConverter converter;
	
	public ConvertRequestAction(IBurpExtenderCallbacks callbacks, IHttpRequestResponse[] https, RequestCommandConverter converter) {
		super(converter.getName());
		this.callbacks = callbacks;
		this.https = https;
		this.converter = converter;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		List<String> commands = convertRequests(converter, https);
		StringSelection ss = new StringSelection(StringUtils.join(commands, "\n"));
		clipboard.setContents(ss, ss);			
	}
	
	private List<String> convertRequests(RequestCommandConverter converter, IHttpRequestResponse[] messages) {
		List<String> commands = new LinkedList<String>();
		for (IHttpRequestResponse message : messages) {
			IRequestInfo req = callbacks.getHelpers().analyzeRequest(message);				
			commands.add(converter.toCommand(message, req));
		}
		return commands;
	}		
}