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
}
