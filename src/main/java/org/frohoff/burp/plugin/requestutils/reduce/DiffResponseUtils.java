package org.frohoff.burp.plugin.requestutils.reduce;

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
		System.out.println("pattern: " + pattern);
		for (String header : headers) {
			try {
				String reqStr = new String(reqBytes);
				String newReqStr = reqStr.replaceAll(Pattern.quote(header) + "\r?\n", "");
				byte[] newReq = newReqStr.getBytes(); //strip header
				IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
				if (pattern.matcher(new String(newRes.getResponse())).find()) {
					System.out.println("removing: " + header);
					reqBytes = newReq;					
				}
			} catch (Exception e) {
				System.out.println(e);
			}			
		}
		return reqBytes;
	}

	public static List<Diff> getStableResponseDiffTemplate(IBurpExtenderCallbacks callbacks, IHttpRequestResponse req) {
		IHttpService service = req.getHttpService();
		byte[] reqBytes = req.getRequest();
		IHttpRequestResponse res1 = callbacks.makeHttpRequest(service, reqBytes);
		sleep();
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