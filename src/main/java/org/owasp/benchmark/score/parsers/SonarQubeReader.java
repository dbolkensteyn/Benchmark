/**
 * OWASP Benchmark Project
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Benchmark Project For details, please see
 * <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
 *
 * The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details
 *
 * @author Dave Wichers <a href="https://www.aspectsecurity.com">Aspect Security</a>
 * @created 2015
 */

package org.owasp.benchmark.score.parsers;

import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.benchmark.score.BenchmarkScore;

public class SonarQubeReader extends Reader {

    private static final Pattern BENCHMARK_TEST_REGEX = Pattern.compile(BenchmarkScore.BENCHMARKTESTNAME + "([0-9]++)\\.java");
    private static final Map<String, Integer> RULE_TO_CWE = ImmutableMap.<String, Integer>builder()
      .put("SonarSecurity:S3649", 89)
      .build();

    public TestResults parse(File f) {
        TestResults tr = new TestResults( "SonarQube" ,false,TestResults.ToolType.SAST);

        try (InputStreamReader isr = new InputStreamReader(new FileInputStream(f))) {
            Gson gson = new Gson();
            Map json = gson.fromJson(isr, Map.class);

            long total = Math.round((double)json.get("total"));
            long page = Math.round((double)json.get("p"));
            long pageSize = Math.round((double)json.get("ps"));

            if (page != 1) {
                throw new IllegalArgumentException("Expected the page number to be 1");
            } else if (total > pageSize) {
                throw new IllegalArgumentException("Too many issues for the given page size");
            }

            for (Map issue: (List<Map>)json.get("issues")) {
                String component = (String)issue.get("component");
                Matcher matcher = BENCHMARK_TEST_REGEX.matcher(component);
                if (!matcher.find()) {
                    continue;
                }
                int testCaseNumber = Integer.valueOf(matcher.group(1));

                String rule = (String)issue.get("rule");
                if (!RULE_TO_CWE.containsKey(rule)) {
                    continue;
                }
                int cwe = RULE_TO_CWE.get(rule);

                String message = (String)issue.get("message");

                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testCaseNumber);
                tcr.setCWE(cwe);
                tcr.setEvidence(message);

                tr.put(tcr);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return tr;
    }

}
