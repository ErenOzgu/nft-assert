| From | To | tcp/22 | tcp/80 | tcp/443 | tcp/3306 | udp/53 | icmp |
|---|---|---|---|---|---|---|---|
| fw | net | accept | accept | accept | accept | accept | accept |
| net | fw | accept | drop | accept | drop | drop | accept |
