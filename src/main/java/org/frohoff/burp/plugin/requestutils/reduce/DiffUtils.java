package org.frohoff.burp.plugin.requestutils.reduce;

import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.regex.Pattern;

import name.fraser.neil.plaintext.diff_match_patch;
import name.fraser.neil.plaintext.diff_match_patch.Diff;
import name.fraser.neil.plaintext.diff_match_patch.Operation;

import org.frohoff.burp.plugin.requestutils.StringUtils;

public class DiffUtils {
	private static final String WHITESPACE = " \t\n\r";	
	
	// TODO reimplement with ListIterator for performance
	public static List<Diff> reduceDiffs(List<Diff> diffs) {
		int i = 0;
		while (i < diffs.size()) {
			int left = diffs.size() - i;
			if (left >= 1 && reduceSingle(diffs, i))
				continue;
			if (left >= 2 && reduceDouble(diffs, i))
				continue;
			if (left >= 3 && reduceTriple(diffs, i))
				continue;
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
			int aLastSpace = StringUtils.lastIndexOf(a.text, WHITESPACE);
			int bFirstSpace = StringUtils.firstIndexOf(b.text, WHITESPACE);
			int cFirstSpace = StringUtils.firstIndexOf(c.text, WHITESPACE);			
			if (aLastSpace != -1 && aLastSpace != a.text.length()-1 && bFirstSpace != 0 && cFirstSpace != 0) { // source has space and sinks aren't bounded by space
				String chunk = a.text.substring(aLastSpace+1);
				a.text = a.text.substring(0, aLastSpace+1);
				b.text = chunk + b.text;
				c.text = chunk + c.text;
				return true;
			}
		} else if (oppositeDiffOps(a,b) && c.operation == Operation.EQUAL) { // C1,C2,E
			int aLastSpace = StringUtils.lastIndexOf(a.text, WHITESPACE);
			int bLastSpace = StringUtils.lastIndexOf(b.text, WHITESPACE);
			int cFirstSpace = StringUtils.firstIndexOf(c.text, WHITESPACE);			
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

	public static boolean oppositeDiffOps(Diff a, Diff b) {
		return a.operation == Operation.DELETE && b.operation == Operation.INSERT
				|| a.operation == Operation.INSERT && b.operation == Operation.DELETE;
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
	
	public static boolean diffCompatable(List<Diff> template, List<Diff> diffs) {
		ListIterator<Diff> tempIter = template.listIterator();
		ListIterator<Diff> diffsIter = diffs.listIterator();
		
		while (tempIter.hasNext() && diffsIter.hasNext()) {
			Diff tempDiff = tempIter.next();
			Diff diff = diffsIter.next();
			
			if (tempDiff.equals(diff)) {
				continue;
			} else if (tempDiff.operation != Operation.EQUAL && diff.operation == Operation.EQUAL) {
				
			} else { // both EQUAL but non-matching text or EQUAL tempDiff with non-EQUAL diff
				return false;
			}
		}
		return true;
		
	}	
	
	public static Pattern diffTemplateToPattern(List<Diff> diffs) {
		Iterator<Diff> i = diffs.iterator();
		StringBuilder sb = new StringBuilder();
		while (i.hasNext()) {
			Diff diff = i.next();
			if (diff.operation == Operation.EQUAL) {
				sb.append(Pattern.quote(diff.text));
			} else {
				sb.append(".*");
			}
		}
		return Pattern.compile(sb.toString().replaceAll("(\\.\\*)+", ".*"));
	}
}
