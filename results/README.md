## Generate SonarQube results

Setup a local SonarQube instance with both the sonar-java and sonar-security plugins installed.

Analyze the OWASP Benchmark project:
```
mvn clean package org.sonarsource.scanner.maven:sonar-maven-plugin:LATEST:sonar -f ../pom.xml
```

Export the list of issues of the OWASP Benchmark project into a JSON file:
```
curl "http://localhost:9000/api/issues/search?componentKeys=org.owasp:benchmark&statuses=OPEN&ps=500" -o Benchmark_1.2-sonarqube.json
```

Run the scorecard generator.
