package org.frohoff.burp.plugin.requestutils;

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
import javax.swing.JMenu;
import javax.swing.JMenuItem;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class RequestUtilsBurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final Set<Byte> CONTEXTS = new HashSet<Byte>(Arrays.asList(
			CONTEXT_MESSAGE_EDITOR_REQUEST, CONTEXT_MESSAGE_VIEWER_REQUEST, CONTEXT_PROXY_HISTORY)); 
	
	private IBurpExtenderCallbacks callbacks = null;
	private PrintWriter out = null;
	
	private Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		
	public interface RequestCommandConverter {
		public String toCommand(IHttpRequestResponse http);
		public String getName();
	}
	
	public class CurlRequestCommandConverter implements RequestCommandConverter {
		@Override
		public String toCommand(IHttpRequestResponse message) {
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

		@Override
		public String getName() {
			return "curl";
		}
	}
	
	public class ConvertRequestAction extends AbstractAction {
		private static final long serialVersionUID = -1305935558053936713L;
		private final IHttpRequestResponse[] https;
		private final RequestCommandConverter converter;
		
		public ConvertRequestAction(IHttpRequestResponse[] https, RequestCommandConverter converter) {
			super(converter.getName());
			this.https = https;
			this.converter = converter;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			List<String> commands = convertRequests(converter, https);
			out.println("commands: " + commands);
			StringSelection ss = new StringSelection(join(commands, "\n"));
			clipboard.setContents(ss, ss);			
		}
		
		private List<String> convertRequests(RequestCommandConverter converter, IHttpRequestResponse[] messages) {
			List<String> commands = new LinkedList<String>();
			for (IHttpRequestResponse message : messages) {
				commands.add(converter.toCommand(message));
			}
			return commands;
		}		
	}
	
	protected RequestCommandConverter[] getConverters() {
		return new RequestCommandConverter[] { new CurlRequestCommandConverter() };
	}
	
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
			final RequestCommandConverter[] converters = getConverters();
			final IHttpRequestResponse[] https = invocation.getSelectedMessages();
			return Arrays.asList((JMenuItem) new JMenu("Convert to Command"){
				
//				@Override
//				public MenuElement[] getSubElements() {
//					MenuElement[] subElements = new MenuElement[converters.length];
//					for (int i = 0; i < subElements.length; i++) {
//						subElements[i] = new JMenuItem(new ConvertRequestAction(https, converters[i])); 
//					}
//					return subElements;
//				}
				
				{
					for (RequestCommandConverter converter : converters) {
						add(new JMenuItem(new ConvertRequestAction(https, converter))); 
					}
				}
			});
		} else {
			return new ArrayList<JMenuItem>();
		}
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
