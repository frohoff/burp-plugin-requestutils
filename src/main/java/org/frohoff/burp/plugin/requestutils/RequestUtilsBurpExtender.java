package org.frohoff.burp.plugin.requestutils;

import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_PROXY_HISTORY;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

import org.frohoff.burp.plugin.requestutils.command.CurlRequestCommandConverter;
import org.frohoff.burp.plugin.requestutils.command.RequestCommandConverter;

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
	
	private Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		
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
	
	protected RequestCommandConverter[] getConverters() {
		return new RequestCommandConverter[] { new CurlRequestCommandConverter() };
	}
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		if (CONTEXTS.contains(invocation.getInvocationContext())) {
			final RequestCommandConverter[] converters = getConverters();
			final IHttpRequestResponse[] https = invocation.getSelectedMessages();
			return Arrays.asList((JMenuItem) new JMenu("Copy as Command"){{
					for (RequestCommandConverter converter : converters) {
						add(new JMenuItem(new ConvertRequestAction(https, converter))); 
					}
			}});
		} else {
			return new ArrayList<JMenuItem>();
		}
	}
}
