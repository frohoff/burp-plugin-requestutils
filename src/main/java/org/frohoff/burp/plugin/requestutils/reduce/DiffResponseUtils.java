package org.frohoff.burp.plugin.requestutils.reduce;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import name.fraser.neil.plaintext.diff_match_patch.Diff;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

public class DiffResponseUtils {	
	public static byte[] getReducedRequest(IBurpExtenderCallbacks callbacks, IHttpRequestResponse req) {		
		List<Diff> template = getStableResponseDiffTemplate(callbacks, req);
		IHttpService service = req.getHttpService();
		byte[] reqBytes = req.getRequest();
		IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(reqBytes);		
		List<String> headers = reqInfo.getHeaders();
		Pattern pattern = DiffUtils.diffTemplateToPattern(template);
		if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE 
				|| reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			byte[] body = Arrays.copyOfRange(reqBytes, reqInfo.getBodyOffset(), reqBytes.length);
			String[] params = new String(body).split("&");
			for (String param : params) {
				reqBytes = tryStrippedRequest(callbacks, service, reqBytes, param, pattern);	
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
						reqBytes = tryStrippedRequest(callbacks, service, reqBytes, param, pattern);	
					}
				}
			} else if (header.startsWith("Cookie: ")) {
				String[] pieces = header.split("\\s*:\\s*",2);
				String[] cookies = header.replaceAll("^Cookie: ", "").split(";");
				for (String cookie : cookies) {
					reqBytes = tryStrippedRequest(callbacks, service, reqBytes, cookie, pattern);						
				}
			} else {
				reqBytes = tryStrippedRequest(callbacks, service, reqBytes, header + "\r\n", pattern);
			}
		}
		return reqBytes;
	}

	private static byte[] tryStrippedRequest(IBurpExtenderCallbacks callbacks, IHttpService service, byte[] reqBytes, String content, Pattern pattern) {
		String reqStr = new String(reqBytes);
		String newReqStr = reqStr.replaceAll(Pattern.quote(content), "");
		byte[] newReq = newReqStr.getBytes(); //strip header
		IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
		if (pattern.matcher(new String(newRes.getResponse())).find()) {
			System.out.println("removing: '" + content + "'");
			reqBytes = newReq;					
		}		
		return reqBytes;
	}
	
	public static List<Diff> getStableResponseDiffTemplate(IBurpExtenderCallbacks callbacks, IHttpRequestResponse req) {
		IHttpService service = req.getHttpService();
		byte[] reqBytes = req.getRequest();
		IHttpRequestResponse res1 = callbacks.makeHttpRequest(service, reqBytes);
		sleep(); // exaggerate differences due to timestamps in response
		IHttpRequestResponse res2 = callbacks.makeHttpRequest(service, reqBytes);
		List<Diff> template = DiffUtils.diff(new String(res1.getResponse()), new String(res2.getResponse()));
		return template;
	}

	private static void sleep() {
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			Thread.interrupted();
		}
	}		
}