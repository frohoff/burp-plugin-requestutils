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
	private static final int NUM_STABILITY_TESTS = 3;
	private static final String WHITESPACE = " \t\n\r";
	
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
				List<Diff> newDiff = diff(new String(res.getResponse()), new String(newRes.getResponse()));
				//System.out.println(newDiff);
				compareDiffs(newDiff, template);
				req = newReq;
			} catch (Exception e) {
				System.out.println(e);
			}			
		}
		
		return req;
	}

	public static List<Diff> getStableResponseDiffTemplate(IBurpExtenderCallbacks callbacks, IHttpService service, byte[] req) {
		List<byte[]> responses = new ArrayList<byte[]>(NUM_STABILITY_TESTS);
		List<List<Diff>> diffs = new ArrayList<List<Diff>>(NUM_STABILITY_TESTS*NUM_STABILITY_TESTS);
		for (int i = 0; i < NUM_STABILITY_TESTS; i++) {
			System.out.println("making init request");
			responses.add(callbacks.makeHttpRequest(service, req).getResponse());
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {				
				e.printStackTrace();
			}
		}
		List<Diff> template = null;
		for (int i = 0; i < responses.size(); i++) {
			for (int j = i + 1; j < responses.size(); j++) {
				if (template == null) {
					template = diff(new String(responses.get(i)), new String(responses.get(j)));
				} else {
					List<Diff> newDiffs = diff(new String(responses.get(i)), new String(responses.get(j)));
					compareDiffs(template, newDiffs);
					
				}				
			}
		}
		return template;
	}

	public static List<Diff> diff(String a, String b) {
		List<Diff> diff = new diff_match_patch().diff_main(a, b);
		diff = reduceDiffs(diff);
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

	public static List<Diff> reduceDiffs(List<Diff> diffs) {
		// E, D, A => ED, EA
		// D, A, E => DE, AE
		// D, A, D, A => DD,AA
		int i = 0;
		while (i < diffs.size()) {
			int left = diffs.size() - i;
			if (left >= 1 && reduceSingle(diffs, i))
				continue;
			if (left >= 2 && reduceDouble(diffs, i))
				continue;
			if (left >= 3 && reduceTriple(diffs, i))
				continue;
//			if (left >= 4 && reduceQuadruple(diffs, i))
//				continue;
			i++;
		}
		
		return diffs;
	}
	
	public static boolean reduceSingle(List<Diff> diffs, int i) {
		Diff a = diffs.get(i);
		if (a.text.length() == 0) {
			diffs.remove(i);
			return true;
		}
		return false;
	}
	
	public static boolean reduceDouble(List<Diff> diffs, int i) {
		Diff a = diffs.get(i);
		Diff b = diffs.get(i + 1);
		if (a.operation == b.operation) { // combine diffs of same op
			a.text = a.text + b.text;
			diffs.remove(i + 1);
			return true;
		}
		return false;
	}
	
	public static boolean reduceTriple(List<Diff> diffs, int i) {
		Diff a = diffs.get(i);
		Diff b = diffs.get(i + 1);
		Diff c = diffs.get(i + 2);
		if (a.operation == Operation.EQUAL && oppositeDiffOps(b,c)) { // E,C1,C2
			int aLastSpace = lastIndexOf(a.text, WHITESPACE);
			int bFirstSpace = firstIndexOf(b.text, WHITESPACE);
			int cFirstSpace = firstIndexOf(c.text, WHITESPACE);			
			if (aLastSpace != -1 && aLastSpace != a.text.length()-1 && bFirstSpace != 0 && cFirstSpace != 0) { // source has space and sinks aren't bounded by space
				String chunk = a.text.substring(aLastSpace+1);
				a.text = a.text.substring(0, aLastSpace+1);
				b.text = chunk + b.text;
				c.text = chunk + c.text;
				return true;
			}
		} else if (oppositeDiffOps(a,b) && c.operation == Operation.EQUAL) { // C1,C2,E
			int aLastSpace = lastIndexOf(a.text, WHITESPACE);
			int bLastSpace = lastIndexOf(b.text, WHITESPACE);
			int cFirstSpace = firstIndexOf(c.text, WHITESPACE);			
			if (aLastSpace != a.text.length()-1 && bLastSpace != b.text.length()-1 && cFirstSpace != -1 && cFirstSpace != 0) {
				String chunk = c.text.substring(0, cFirstSpace);
				a.text = a.text + chunk;
				b.text = b.text + chunk;
				c.text = c.text.substring(cFirstSpace);
				return true;
			}			
		} else if (oppositeDiffOps(a,b) && oppositeDiffOps(b,c)) { // C1 C2 C1
			System.out.println("C1 C2 C1:\na:" + a + "\nb:" + b);
			a.text = a.text + c.text; // append c onto a
			diffs.remove(i + 2); // remove c
			return true;
		}
		return false;
	}
	
//	private static boolean reduceQuadruple(List<Diff> diffs, int i) {
//		Diff a = diffs.get(i);
//		Diff b = diffs.get(i + 1);
//		Diff c = diffs.get(i + 2);
//		Diff d = diffs.get(i + 3);		
//	}

	public static boolean oppositeDiffOps(Diff a, Diff b) {
		return a.operation == Operation.DELETE && b.operation == Operation.INSERT
				|| a.operation == Operation.INSERT && b.operation == Operation.DELETE;
	}
	
	public static int firstIndexOf(String string, String chars) {
		for (int i = 0; i < string.length(); i++) {
			for (int j = 0; j < chars.length(); j++) {
				if (string.charAt(i) == chars.charAt(j)) {
					return i;
				}
			}
				
		}
		return -1;
	}
	
	public static int lastIndexOf(String string, String chars) {
		for (int i = string.length() - 1; i >= 0; i--) {
			for (int j = 0; j < chars.length(); j++) {
				if (string.charAt(i) == chars.charAt(j)) {
					return i;
				}
			}
				
		}
		return -1;	
	}
	
}
