package org.frohoff.burp.plugin.requestutils.reduce;

import java.util.List;
import java.util.regex.Pattern;

import name.fraser.neil.plaintext.diff_match_patch;
import name.fraser.neil.plaintext.diff_match_patch.Diff;
import name.fraser.neil.plaintext.diff_match_patch.Operation;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

public class DiffResponseUtils {	
	public static byte[] getReducedRequest(IBurpExtenderCallbacks callbacks, IHttpRequestResponse req) {		
		List<Diff> template = getStableResponseDiffTemplate(callbacks, req);
		IHttpService service = req.getHttpService();
		byte[] reqBytes = req.getRequest();
		IHttpRequestResponse res = callbacks.makeHttpRequest(service, reqBytes); // control
		IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(reqBytes);		
		List<String> headers = reqInfo.getHeaders();
		for (String header : headers) {
			System.out.println("removing: " + header);
			try {
				String reqStr = new String(reqBytes);
				String newReqStr = reqStr.replaceAll(Pattern.quote(header) + "\r?\n", "");
				byte[] newReq = newReqStr.getBytes(); //strip header
				IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
				List<Diff> newDiff = diff(new String(res.getResponse()), new String(newRes.getResponse()));
				//System.out.println(newDiff);
				compareDiffs(newDiff, template);
				System.out.println(new String(reqBytes));
				reqBytes = newReq;
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
		//sleep();
		IHttpRequestResponse res2 = callbacks.makeHttpRequest(service, reqBytes);
		List<Diff> template = diff(new String(res1.getResponse()), new String(res2.getResponse()));
		return template;
	}

	private static void sleep() {
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
		}
	}

	public static List<Diff> diff(String a, String b) {
		List<Diff> diff = new diff_match_patch().diff_main(a, b);
		diff = DiffUtils.reduceDiffs(diff);
		return diff;		
	}
	
	public static void compareDiffs(List<Diff> template, List<Diff> newDiffs) {
		if (newDiffs.size() == template.size())	{
			for (int i = 0; i < template.size(); i++) {
				if (template.get(i).equals(newDiffs.get(i))) {} // EQUAL cases
				else if (template.get(i).operation != Operation.EQUAL 
						&& newDiffs.get(i).operation != Operation.EQUAL) {}
				else
					throw new RuntimeException("can't find stable diff template");
			}
		} else {
			throw new RuntimeException("can't find stable diff template");	
		}		
	}	


	
}
