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

public class ReduceRequestAction extends AbstractAction {	
	private static final long serialVersionUID = 4561751876702401810L;
	private static final Executor executor = Executors.newFixedThreadPool(5);
	
	private final IBurpExtenderCallbacks callbacks;
	private final IHttpRequestResponse[] reqs;
	
	public ReduceRequestAction(String name, IBurpExtenderCallbacks callbacks, IHttpRequestResponse... reqs) {
		super(name);
		this.callbacks = callbacks;
		this.reqs = reqs;		
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		for (final IHttpRequestResponse req : reqs) {
			final IHttpService service = req.getHttpService();
			executor.execute(new Runnable(){
				@Override
				public void run() {
					final byte[] reqBytes = getReducedRequest(req);
					final boolean wasReduced = ! Arrays.equals(req.getRequest(), reqBytes);
					SwingUtilities.invokeLater(new Runnable(){
						@Override
						public void run() {
							callbacks.sendToRepeater(
								service.getHost(), service.getPort(), service.getProtocol().equalsIgnoreCase("https")
								, reqBytes, wasReduced ? "Reduced" : "Couldn't Reduce");
						}						
					});					
				}
			});			
		}
	}			
	
	protected byte[] getReducedRequest(IHttpRequestResponse req) {
		IHttpService service = req.getHttpService();
		List<Diff> diffTemplate = createDiffTemplate(req);
		byte[] reqBytes = req.getRequest();
		IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(reqBytes);		
		List<String> headers = reqInfo.getHeaders();
		Pattern tmplPattern = DiffUtils.diffTemplateToPattern(diffTemplate);
		if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE 
				|| reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			byte[] body = Arrays.copyOfRange(reqBytes, reqInfo.getBodyOffset(), reqBytes.length);
			String[] params = new String(body).split("&");
			for (String param : params) {
				reqBytes = tryStrippedRequest(tmplPattern, service, reqBytes, param, "&");	
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
						reqBytes = tryStrippedRequest(tmplPattern, service, reqBytes, param, "&");	
					}
				}
			} else if (header.startsWith("Cookie: ")) {
				String[] pieces = header.split("\\s*:\\s*",2);
				if (pieces.length == 2) {
					String[] cookies = pieces[1].split(";");
					for (String cookie : cookies) {
						reqBytes = tryStrippedRequest(tmplPattern, service, reqBytes, cookie, "\\s*;\\s*");						
					}					
				}
			} else {
				reqBytes = tryStrippedRequest(tmplPattern, service, reqBytes, header, "\r\n");
			}
		}
		return reqBytes;
	}

	protected byte[] tryStrippedRequest(Pattern templPattern, IHttpService service, byte[] reqBytes
										, String content, String delimRegex) {
		System.out.println("trying to remove: " + content);
		String reqStr = new String(reqBytes);
		String newReqStr = reqStr.replaceAll(Pattern.quote(content) + "(" + delimRegex + ")?", ""); //strip header
		byte[] newReq = newReqStr.getBytes(); 
		IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
		if (newRes.getResponse() != null && templPattern.matcher(new String(newRes.getResponse())).find()) {
			reqBytes = newReq;					
		}		
		return reqBytes;
	}
	
	protected List<Diff> createDiffTemplate(IHttpRequestResponse req) {
		IHttpService service = req.getHttpService();
		byte[] reqBytes = req.getRequest();
		IHttpRequestResponse res1 = request(service, reqBytes);
		sleep(); // exaggerate differences due to timestamps in response
		IHttpRequestResponse res2 = request(service, reqBytes);
		List<Diff> template = DiffUtils.diff(new String(res1.getResponse()), new String(res2.getResponse()));
		return template;
	}

	protected IHttpRequestResponse request(IHttpService service, byte[] reqBytes) {
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