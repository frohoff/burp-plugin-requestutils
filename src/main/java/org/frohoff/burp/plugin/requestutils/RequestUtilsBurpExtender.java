package org.frohoff.burp.plugin.requestutils;

import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST;
import static burp.IContextMenuInvocation.CONTEXT_PROXY_HISTORY;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import org.frohoff.burp.plugin.requestutils.command.CurlRequestCommandConverter;
import org.frohoff.burp.plugin.requestutils.command.RequestCommandConverter;
import org.frohoff.burp.plugin.requestutils.reduce.DiffResponseUtils;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class RequestUtilsBurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final Set<Byte> COPY_AS_CONTEXTS = new HashSet<Byte>(Arrays.asList(
			CONTEXT_MESSAGE_EDITOR_REQUEST, CONTEXT_MESSAGE_VIEWER_REQUEST, CONTEXT_PROXY_HISTORY)); 
	
	private IBurpExtenderCallbacks callbacks = null;
	
			
	protected RequestCommandConverter[] getConverters() {
		return new RequestCommandConverter[] { new CurlRequestCommandConverter() };
	}
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.registerContextMenuFactory(this);
		callbacks.setExtensionName("Request-Utils");
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> items = new LinkedList<JMenuItem>(); 
		if (COPY_AS_CONTEXTS.contains(invocation.getInvocationContext())) {
			final RequestCommandConverter[] converters = getConverters();
			final IHttpRequestResponse[] https = invocation.getSelectedMessages();
			items.add(new JMenu("Copy as Command"){{
					for (RequestCommandConverter converter : converters) {
						add(new JMenuItem(new ConvertRequestAction(callbacks, https, converter))); 
					}
			}});
			//TODO: handle/prevent multiple selected requests
			items.add(new JMenuItem(new DiffResponseUtils("Reduce Request", callbacks, invocation.getSelectedMessages()[0])));			
		} 
		return items;
	}
}
