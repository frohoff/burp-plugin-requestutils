package org.frohoff.burp.plugin.curl;

import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_PROXY_HISTORY;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.JMenuItem;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class CurlBurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final Set<Byte> CONTEXTS = new HashSet<Byte>(Arrays.asList(
			CONTEXT_MESSAGE_EDITOR_REQUEST, CONTEXT_MESSAGE_VIEWER_REQUEST, CONTEXT_PROXY_HISTORY)); 
	
	private IBurpExtenderCallbacks callbacks = null;
	private PrintWriter out = null;
	
	private Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		out = new PrintWriter(this.callbacks.getStdout());
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		out.println("creating menu items");
		if (CONTEXTS.contains(invocation.getInvocationContext())) {
			return Arrays.asList((JMenuItem) new JMenuItem(new AbstractAction("copy as curl"){
				@Override
				public void actionPerformed(ActionEvent e) {
					List<String> commands = convertToCurlCommand(invocation.getSelectedMessages());
					out.println("commands: " + commands);
					StringSelection ss = new StringSelection(join(commands, "\n"));
					clipboard.setContents(ss, ss);
				}
			}));
		} else {
			return new ArrayList<JMenuItem>();
		}
	}
	
	private List<String> convertToCurlCommand(IHttpRequestResponse[] messages) {
		List<String> commands = new LinkedList<String>();
		for (IHttpRequestResponse message : messages) {
			commands.add(convertToCurlCommand(message));
		}
		return commands;
	}

	private String convertToCurlCommand(IHttpRequestResponse message) {
		IRequestInfo req = callbacks.getHelpers().analyzeRequest(message);
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
		return join(comm, " ");
	}	
	
	private static String join(Iterable<? extends Object> iterable, String del) {
		StringBuffer sb = new StringBuffer();
		boolean first = true;
		for (Object o : iterable) {
			if (!first)
				sb.append(del);
			sb.append(o.toString());
			first = false;
		}
		return sb.toString();
	}
}
