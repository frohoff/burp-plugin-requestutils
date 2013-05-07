package org.frohoff.burp.plugin.requestutils.reduce;

import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import javax.swing.AbstractAction;
import javax.swing.SwingUtilities;

import name.fraser.neil.plaintext.diff_match_patch.Diff;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

public class DiffResponseUtils extends AbstractAction {	
	private static final long serialVersionUID = 4561751876702401810L;

	private static Executor executor = Executors.newFixedThreadPool(5);
	
	private final IBurpExtenderCallbacks callbacks;
	private final IHttpRequestResponse req;
	private final IHttpService service;
	
	public DiffResponseUtils(String name, IBurpExtenderCallbacks callbacks, IHttpRequestResponse req) {
		super(name);
		this.callbacks = callbacks;
		this.req = req;
		this.service = req.getHttpService();
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		executor.execute(new Runnable(){
			@Override
			public void run() {
				System.out.println("reducing request");
				final byte[] reqBytes = getReducedRequest();
				final boolean reduced = Arrays.equals(req.getRequest(), reqBytes);
				SwingUtilities.invokeLater(new Runnable(){
					@Override
					public void run() {
						callbacks.sendToRepeater(service.getHost(), service.getPort()
								, service.getProtocol().equalsIgnoreCase("https"), reqBytes, reduced ? "Reduced" : "Couldn't Reduce");
					}						
				});					
			}
		});
	}			
	
	protected byte[] getReducedRequest() {		
		List<Diff> diffTemplate = createDiffTemplate();
		byte[] reqBytes = req.getRequest();
		IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(reqBytes);		
		List<String> headers = reqInfo.getHeaders();
		Pattern templatePattern = DiffUtils.diffTemplateToPattern(diffTemplate);
		if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE 
				|| reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			byte[] body = Arrays.copyOfRange(reqBytes, reqInfo.getBodyOffset(), reqBytes.length);
			String[] params = new String(body).split("&");
			for (String param : params) {
				reqBytes = tryStrippedRequest(templatePattern, reqBytes, param, "&");	
			}			
		}		
		for (String header : headers) {
			if (header.startsWith(reqInfo.getMethod())) { // METHOD/PATH line
				String[] pieces = header.split(" ");
				String uri = pieces[1];
				String[] uriParts = uri.split("\\?");
				if (uriParts.length == 2) {
					String[] params = uriParts[1].split("&");
					for (String param : params) {
						reqBytes = tryStrippedRequest(templatePattern, reqBytes, param, "&");	
					}
				}
			} else if (header.startsWith("Cookie: ")) {
				String[] pieces = header.split("\\s*:\\s*",2);
				if (pieces.length == 2) {
					String[] cookies = pieces[1].split(";");
					for (String cookie : cookies) {
						reqBytes = tryStrippedRequest(templatePattern, reqBytes, cookie, "\\s*;\\s*");						
					}					
				}
			} else {
				reqBytes = tryStrippedRequest(templatePattern, reqBytes, header, "\r\n");
			}
		}
		return reqBytes;
	}

	protected byte[] tryStrippedRequest(Pattern templatePattern, byte[] reqBytes, String content, String delimiterRegex) {
		String reqStr = new String(reqBytes);
		String newReqStr = reqStr.replaceAll(Pattern.quote(content) + "(" + delimiterRegex + ")?", "");
		byte[] newReq = newReqStr.getBytes(); //strip header
		IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
		if (templatePattern.matcher(new String(newRes.getResponse())).find()) {
			System.out.println("removing: '" + content + "'");
			reqBytes = newReq;					
		}		
		return reqBytes;
	}
	
	protected List<Diff> createDiffTemplate() {
		byte[] reqBytes = req.getRequest();
		IHttpRequestResponse res1 = request(reqBytes);
		sleep(); // exaggerate differences due to timestamps in response
		IHttpRequestResponse res2 = request(reqBytes);
		List<Diff> template = DiffUtils.diff(new String(res1.getResponse()), new String(res2.getResponse()));
		return template;
	}

	protected IHttpRequestResponse request(byte[] reqBytes) {
		return callbacks.makeHttpRequest(service, reqBytes);
	}

	protected void sleep() {
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			Thread.interrupted();
		}
	}
}