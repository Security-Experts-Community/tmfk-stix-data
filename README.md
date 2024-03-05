# Threat Matrix for Kubernetes STIX Data

Microsoft Defender for Cloud [threat matrix for Kubernetes (TMFK)](https://github.com/microsoft/Threat-Matrix-for-Kubernetes) contains attack tactics, techniques and mitigations relevant for Kubernetes environment.

This repository contains the TMFK dataset represented in STIX 2.1 JSON collections. 

## Repository Structure

```
.
├─ build ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Collection folder 
│   ├─ tmfk_strict.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Most recent strict TMFK release
│   ├─ tmfk_attack_compatible.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Most recent ATT&CK compatible TMFK release
│   ├─ tmfk_strict_b885d18.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ TMFK strict collection for commit hash b885d18 of site repo
│   ├─ tmfk_attack_compatible_b885d18.json ∙∙∙∙∙∙ TMFK ATT&CK compatible collection for commit hash b885d18 of site repo
│   └─ [other commits of ATRM]
├─ make.sh ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Build script for *nix and MacOS
└─ make.bat ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Build script for Windows
```

## Supporting Documentation

### [STIX](https://oasis-open.github.io/cti-documentation/)

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

## ATT&CK compatibility

[ATT&CK compatible](https://raw.githubusercontent.com/Security-Experts-Community/tmfk-stix-data/main/build/tmfk_attack_compatible.json) version can be loaded into [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend).

![Pasted image 20240304194014](https://github.com/Security-Experts-Community/tmfk-stix-data/assets/61383585/a1734651-2884-40d0-9501-4f18ffdaebbe)

It uses domain `enterprise-attack` to comply internal contract of ATT&CK Workbench.

![Pasted image 20240304194754](https://github.com/Security-Experts-Community/tmfk-stix-data/assets/61383585/3ba79754-9514-4dfb-8f83-a9c5aecfc3d5)

Mitigations are also included. Furthermore, you can locate a connection to the MITRE ATT&CK mitigations and techniques inside the field `x_mitre_ids` of the related entities.
![Pasted image 20240304194506](https://github.com/Security-Experts-Community/tmfk-stix-data/assets/61383585/c53450f7-cccd-4e85-874e-ede8c5dbafb8)

You can also use the [mitreattack-python](https://mitreattack-python.readthedocs.io/en/latest/) library to process the STIX bundle(see [example.ipynb](https://github.com/Security-Experts-Community/tmfk-stix-data/blob/main/src/example.ipynb)).
