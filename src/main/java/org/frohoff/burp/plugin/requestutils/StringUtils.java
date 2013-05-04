package org.frohoff.burp.plugin.requestutils;

public class StringUtils {

	public static String escapeQuotes(String str) {
		return str.replaceAll("'", "'\"'\"'");
	}

	public static String join(Iterable<? extends Object> iterable, String del) {
		StringBuffer sb = new StringBuffer();
		boolean first = true;
		for (Object o : iterable) {
			if (!first)
				sb.append(del);
			sb.append(o.toString());
			first = false;
		}
		return sb.toString();
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
