# PyVulScan — architecture

## 1. Pipeline (top level)

```mermaid
flowchart LR
    A(Start) --> B{In scope?<br/>loopback / RFC1918}
    B -->|No| X(Refuse<br/>no packets sent)
    B -->|Yes| C(Port scan<br/>TCP connect)
    C --> D{Open ports?}
    D -->|No| Y(Empty report)
    D -->|Yes| E(Fingerprint<br/>banner / HTTP / TLS)
    E --> F(Rule engine<br/>data/rules.json)
    F --> G(Risk scoring<br/>severity + confidence)
    G --> H(Report<br/>JSON + HTML)
    H --> Z(End)
```

## 2. Module layers

```mermaid
flowchart TB
    subgraph CLI
        cli[cli.py<br/>argparse, exit codes]
    end
    subgraph Core
        scope[scope.py<br/>auth guard]
        port[portscan.py<br/>connect scan + banner]
        fp[fingerprint.py<br/>service / version / headers / TLS]
    end
    subgraph Analysis
        eng[checks/engine.py<br/>rule loading + dispatch]
        rules[(data/rules.json<br/>knowledge base)]
        score[scoring.py<br/>CVSS-lite + aggregation]
    end
    subgraph Output
        rep[report.py<br/>JSON + Jinja2 HTML]
    end
    cli --> scope --> port --> fp --> eng
    rules --> eng
    eng --> score --> rep
```

## 3. Data flow (what an object looks like)

```mermaid
classDiagram
    class Target {
        +str ip
        +str label
    }
    class PortResult {
        +int port
        +str status
        +str service
        +str banner
        +float rtt_ms
    }
    class Fingerprint {
        +str product
        +str version
        +dict headers
        +dict tls
    }
    class Finding {
        +str rule_id
        +str title
        +str severity
        +str evidence
        +str remediation
        +float confidence
    }
    class ScanReport {
        +Target target
        +int score
        +list~Finding~ findings
    }
    Target --> PortResult
    PortResult --> Fingerprint
    Fingerprint --> Finding
    Finding --> ScanReport
```

## 4. Stage-1 decision logic (detail of the guard)

```mermaid
flowchart TD
    S([input target]) --> P{parses as literal IP?}
    P -->|no| E1([error: hostnames rejected])
    P -->|yes| Q{in 127/8 or RFC1918?}
    Q -->|no| E2([OutOfScopeError])
    Q -->|yes| R[probe each port<br/>ThreadPoolExecutor]
    R --> T{connect result}
    T -->|refused| C1[closed]
    T -->|timeout| C2[filtered]
    T -->|ok| O[open -> banner grab]
```

## 5. Severity model

| Level | Meaning | Points |
| ----- | ------- | ------ |
| Critical | unauthenticated remote access to sensitive data | 9.0-10.0 |
| High | plaintext admin protocol, missing auth on admin panel | 7.0-8.9 |
| Medium | weak TLS, verbose version disclosure | 4.0-6.9 |
| Low | missing hardening headers, information leakage | 0.1-3.9 |
| Info | service enumeration facts | 0.0 |

Host score = `min(10, max(severity) + 0.1 * (count(medium+)) )`, so one critical
outranks a pile of lows but volume still matters.
