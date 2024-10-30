# Reports, blogs and resources on information security

more links for security resources: https://github.com/mthcht/awesome-lists

- ### Noise storms

  - https://darthnull.org/noisestorms/
  - https://www.greynoise.io/blog/greynoise-reveals-new-internet-noise-storm-secret-messages-and-the-china-connection

- ### Indicators of compromise

  - https://github.com/eset/malware-ioc/

- ### Malware scanners

  - https://bazaar.abuse.ch/browse/
  - https://www.joesandbox.com/#windows
  - https://any.run/
  - https://www.virustotal.com/
  - https://viz.greynoise.io/
  - https://urlscan.io/

- ### APT profiles

  - https://github.com/blackorbird/APT_REPORT/tree/master/summary/2024
  - https://intrusiontruth.wordpress.com/
  - https://andreacristaldi.github.io/APTmap/
  - https://attack.mitre.org/groups/
  - https://www.hhs.gov/sites/default/files/china-based-threat-actor-profiles-tlpclear.pdf
  - https://docs.rapid7.com/insightidr/apt-groups/
  - https://www.mandiant.com/resources/insights/apt-groups
  - https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/
  - https://github.com/CyberRa1/APT-Hub/

- ### Ransomware TTPs and tools

  - https://github.com/crocodyli/ThreatActors-TTPs
  - https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/Tools/AllTools.csv
  - https://gist.github.com/BushidoUK/c6eebfbaaa9058f508233f8551de61ab
  - https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix

- ### Threat intelligence

  - https://blog.malicious.group/
  - https://css.ethz.ch/en/publications.html
  - https://thedfirreport.com/
  - https://www.blackhillsinfosec.com/prompt-zine/
  - https://ti.qianxin.com/blog/
  - https://nattothoughts.substack.com/p/front-company-or-real-business-in
  - https://0reg.dev/blog/
  - https://www.securityweek.com/
  - https://contagiodump.blogspot.com/
  - https://meterpreter.org/
  - https://infosecwriteups.com/
  - https://www.securonix.com/blog/from-cobalt-strike-to-mimikatz-slowtempest/
  - https://www.bloomberg.com/news/features/2018-10-04/the-big-hack-how-china-used-a-tiny-chip-to-infiltrate-america-s-top-companies
  - https://blog.eclecticiq.com/ransomware-in-the-cloud-scattered-spider-targeting-insurance-and-financial-industries
  - https://www.sans.org/blog/defending-against-scattered-spider-and-the-com-with-cybercrime-intelligence/
  - https://jfrog.com/blog/revival-hijack-pypi-hijack-technique-exploited-22k-packages-at-risk/
  - https://0dave.ch/posts/ghmlwr/
  - https://citizenlab.ca/2024/10/should-we-chat-too-security-analysis-of-wechats-mmtls-encryption-protocol/
  - https://redops.at/en/knowledge-base
  - https://www.welivesecurity.com/en/eset-research/mind-air-gap-goldenjackal-gooses-government-guardrails/

- ### Magazines

  - https://phrack.org/
  - https://pagedout.institute/

- ### Presentations from conferences

  - https://media.defcon.org/

# Deploy security research environment

- `git clone https://github.com/JonGood/vulhub-lab.git`
- `cd vulhub-lab`
- replace docker-compose.yml with [vulnhub-lab.yml](vulnhub-lab.yml)
- `sudo docker compose up`
- `sudo docker exec -it kali /bin/bash`
- `sudo docker compose down`
