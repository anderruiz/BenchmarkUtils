/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Joseba Ander Ruiz Ayesta
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.BufferedReader;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SASTDatadogReader extends Reader {

    private static final String VERSION_LINE = "DATADOG TRACER CONFIGURATION {\"version\":\"";

    private static final Set<String> types = new HashSet<>();

    private static final String TYPE = "\"type\":\"";

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().equals("datadog.csv");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("SAST Datadog", true, TestSuiteResults.ToolType.IAST);

        try (BufferedReader reader = new BufferedReader(new StringReader(resultFile.content()))) {
            String firstLine = reader.readLine();
            String[] lastLine = {""};
            String line = "";
            while (line != null) {
                try {
                    line = reader.readLine();
                    processChunk(line, tr, lastLine);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
            tr.setTime(calculateTime(firstLine, lastLine[0]));
        }
        return tr;
    }

    private void processChunk(String chunk, TestSuiteResults tr, String[] lastLine) {
        String testNumber = "00001";
        tr.setToolVersion("1.0");

        String line = String.join("", chunk);
        process(tr, testNumber, Collections.singletonList(line));
    }

    private String calculateTime(final String firstLine, final String lastLine) {
        try {
            String start = firstLine.split(" ")[2];
            String stop = lastLine.split(" ")[2];
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss:SSS");
            Date startTime = sdf.parse(start);
            Date stopTime = sdf.parse(stop);
            long startMillis = startTime.getTime();
            long stopMillis = stopTime.getTime();
            return (stopMillis - startMillis) / 1000 + " seconds";
        } catch (Exception ex) {
            System.err.println("Error parsing dates:" + firstLine + " and " + lastLine);
            return "0 seconds";
        }
    }

    private void process(final TestSuiteResults tr, String testNumber, final List<String> chunk) {
        for (String line : chunk) {
            TestCaseResult tcr = new TestCaseResult();

            String fname = "/" + BenchmarkScore.TESTCASENAME;
            int idx = line.indexOf(fname);
            if (idx != -1) {
                testNumber = line.substring(idx + fname.length(), idx + fname.length() + 5);
            }
            if (line.contains("java-security")) {
                String[] data = line.split(",");
                if ("java-security/sql-string-tainted".equals(data[1])) {
                    tcr.setCWE(Type.SQL_INJECTION.number);
                    tcr.setCategory(Type.SQL_INJECTION.id);
                    try {
                        tcr.setNumber(Integer.parseInt(testNumber));
                    } catch (NumberFormatException e) {
                        System.out.println("> Parse error: " + line);
                    }
                    if (tcr.getCWE() != 0) {
                        tr.put(tcr);
                    }
                }
            }
        }
    }

    private enum Type {
        COMMAND_INJECTION(78),
        WEAK_HASH("crypto-bad-mac", 328),
        WEAK_CIPHER("crypto-bad-ciphers", 327),
        HEADER_INJECTION(113),
        INSECURE_COOKIE("cookie-flags-missing", 614),
        LDAP_INJECTION(90),
        PATH_TRAVERSAL(22),
        REFLECTION_INJECTION(0),
        SQL_INJECTION(89),
        STACKTRACE_LEAK(209),
        TRUST_BOUNDARY_VIOLATION(501),
        WEAK_RANDOMNESS("crypto-weak-randomness", 330),
        XPATH_INJECTION(643),
        XSS("reflected-xss", 79);

        private final int number;

        private final String id;

        Type(final int number) {
            this.number = number;
            id = name().toLowerCase().replaceAll("_", "-");
        }

        Type(final String id, final int number) {
            this.number = number;
            this.id = id;
        }

        private static Type secureValueOf(String value) {
            for (Type type : values()) {
                if (type.name().equals(value)) {
                    return type;
                }
            }
            return null;
        }
    }
}
