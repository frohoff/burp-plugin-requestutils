package org.frohoff.burp.plugin.requestutils.reduce;

import java.util.ArrayList;
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

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		List<Diff> diffs = new diff_match_patch().diff_main("foo\nbar\nbaz", "foo\nboo\nfar\nbaz");
		System.out.println("done");

		

	}

	private static int responseStabilityTests = 10;
	public static byte[] getReducedRequest(IBurpExtenderCallbacks callbacks, IHttpService service, byte[] req) {		
		List<Diff> template = getStableResponseDiffTemplate(callbacks, service, req);
		IHttpRequestResponse res = callbacks.makeHttpRequest(service, req); // control
		IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(req);		
		List<String> headers = reqInfo.getHeaders();
		for (String header : headers) {
			System.out.println("removing: " + header);
			try {
				String reqStr = new String(req);
				String newReqStr = reqStr.replaceAll(Pattern.quote(header) + "\n", "");
				byte[] newReq = newReqStr.getBytes(); //strip header
				IHttpRequestResponse newRes = callbacks.makeHttpRequest(service, newReq);
				List<Diff> newDiff = new diff_match_patch().diff_main(new String(res.getResponse()), new String(newRes.getResponse()));
				//System.out.println(newDiff);
				compareDiffs(newDiff, template);
				req = newReq;
			} catch (Exception e) {
				System.out.println(e);
			}			
		}
		
		return req;
	}

	private static List<Diff> getStableResponseDiffTemplate(IBurpExtenderCallbacks callbacks, IHttpService service, byte[] req) {
		List<byte[]> responses = new ArrayList<byte[]>(responseStabilityTests);
		List<List<Diff>> diffs = new ArrayList<List<Diff>>(responseStabilityTests*responseStabilityTests);
		for (int i = 0; i < responseStabilityTests; i++) {
			responses.add(callbacks.makeHttpRequest(service, req).getResponse());
		}
		List<Diff> template = null;
		for (int i = 0; i < responses.size(); i++) {
			for (int j = i + 1; j < responses.size(); j++) {
				if (template == null) {
					template = new diff_match_patch().diff_main(new String(responses.get(i)), new String(responses.get(j)));
				} else {
					List<Diff> newDiffs = new diff_match_patch().diff_main(new String(responses.get(i)), new String(responses.get(j)));
					compareDiffs(template, newDiffs);
					
				}				
			}
		}
		return template;
	}

	private static void compareDiffs(List<Diff> template, List<Diff> newDiffs) {
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
