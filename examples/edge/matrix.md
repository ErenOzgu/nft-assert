| From | To | tcp/22 | tcp/25 | tcp/80 | tcp/443 | tcp/8080 | udp/53 | icmp |
|---|---|---|---|---|---|---|---|---|
| fw | wan | accept | accept | accept | accept | accept | accept | accept |
| fw | lan | accept | accept | accept | accept | accept | accept | accept |
| fw | dmz | accept | accept | accept | accept | accept | accept | accept |
| wan | fw | drop | drop | drop | drop | accept | drop | accept |
| wan | lan | drop | drop | drop | drop | accept | drop | drop |
| wan | dmz | drop | drop | drop | drop | accept | drop | drop |
| lan | fw | accept | drop | drop | drop | drop | drop | accept |
| lan | wan | accept | accept | accept | accept | accept | accept | accept |
| lan | dmz | accept | drop | accept | accept | drop | drop | accept |
| dmz | fw | drop | drop | drop | drop | drop | drop | accept |
| dmz | wan | drop | reject | accept | accept | drop | drop | drop |
| dmz | lan | drop | drop | drop | drop | drop | drop | drop |
