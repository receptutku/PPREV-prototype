# R3: notarised sessions against public pages of production servers

Transport experiment only. No login, no account, no credentials, no query parameters; three GET
requests per target (two plain, one notarised), User-Agent `pprev-probe/0.1 (research prototype;
one request per run)`. The notary ran in the same process with a fixed, public attestation key and
the Mozilla root store: no evidence of an independent notary deployment. No response content is
stored; records hold byte counts, positions of differing bytes, status line, Content-Type, timings.
tlsn does not expose the negotiated cipher suite (recorded as null); its MPC mode offers only
TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256.

| Target | Status | Notarised bytes | Presentation (server identity, t_att) | Repeated plain responses |
|---|---|---:|---|---|
| www.turkiye.gov.tr/robots.txt (probe-1, first probe version) | 200 | 481 | verified | same length (481), bytes differ |
| parselsorgu.tkgm.gov.tr/robots.txt | 302 redirect | 993 | verified | identical; notarised one differs in 2 header bytes |
| eservices.landregistry.gov.uk/robots.txt | 200 | 958 | verified | lengths 1083, 958, 958 (notarised): not equal |
| www.turkiye.gov.tr/tapu-bilgileri-sorgulama (public service page) | 200 | 17,984 | verified | lengths 17,986, 17,997, 17,984: not equal |

All four sessions used TLS 1.2 with a 3-certificate chain to a Mozilla root, and the presentation
verified against those roots with the target's DNS name. Single observations; the MPC-TLS times
(0.3-0.5 s for probe-2, 7.7 s for probe-1) are not a distribution and are not compared.

What this supports: TLSNotary v0.1.0-alpha.15 in MPC mode completes sessions with these production
servers, including an 18 KB HTML page, and the probe verifies the presentation server identity and extracts t_att
using a real certificate chain. It does not invoke the application predicate-policy verifier.

What it does not support: anything about authenticated record views (none was requested), about a
fixed record layout (two of four targets returned different total response lengths for identical
requests; neither equal nor unequal totals establish the stability of particular field offsets),
or about latency over a wide-area notary.
