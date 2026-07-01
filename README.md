Cloud Identity Security Engineering

«IAM permissions are not a list. They are a graph.»

Cloud Identity Security Engineering is a practitioner-focused research project exploring how AWS Identity and Access Management (IAM) configurations can be modeled as authorization graphs to identify privilege escalation, lateral movement, and identity-based attack paths.

Instead of inspecting IAM policies in isolation, this project builds tooling that discovers relationships across policies, trust boundaries, service roles, and cross-account assumptions.

The repository accompanies the Cloud Identity Security Engineering Hashnode series, where each article introduces a new security engineering capability backed by working Go implementations, threat modeling, attack-path analysis, and detection engineering.

---

Core Philosophy

Modern cloud environments are composed of interconnected identities rather than isolated permissions.

A single IAM policy may appear harmless on its own. However, when combined with trust relationships, resource policies, delegated permissions, and service roles, it can become part of a multi-stage privilege escalation path.

The objective of this project is to model those relationships explicitly.

Rather than asking:

«"Does this policy look dangerous?"»

this project asks:

«"What can this identity eventually become?"»

That shift—from policy inspection to graph traversal—forms the foundation of this repository.

---

Project Objectives

The objective of this repository is to build tooling for:

- Parsing AWS IAM and trust policies.
- Constructing authorization graphs.
- Modeling cross-account role assumption paths.
- Identifying privilege escalation opportunities.
- Detecting identity-based attack paths.
- Engineering CloudTrail detections from observable behavior.
- Mapping findings to MITRE ATT&CK and common compliance frameworks.

---

Repository Structure

.
├── analysis/
│   └── rr-001/
│       ├── attack-paths.md
│       ├── compliance-mapping.md
│       ├── detections.md
│       ├── mitre-mapping.md
│       └── report.md
│
├── cmd/
│   ├── attackpath/
│   ├── iamscan/
│   └── policyparser/
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── compliance-framework.md
│   ├── series-overview.md
│   └── diagrams/
│
├── examples/
│   ├── iam-policies/
│   ├── attack-scenarios/
│   ├── cloudtrail-logs/
│   └── compliance-reports/
│
├── internal/
│   ├── attack/
│   ├── detection/
│   ├── graph/
│   ├── iam/
│   ├── model/
│   └── parser/
│
└── scripts/

---

Engineering Components

IAM Parser

Parses AWS IAM and trust policies into strongly typed Go structures while preserving policy semantics for later analysis.

Current focus includes:

- Identity policies
- Trust policies
- Actions
- Resources
- Principals
- Conditions
- Policy normalization

---

Identity Graph

Builds directed authorization graphs representing relationships between identities, permissions, and trust boundaries.

Future graph analysis includes:

- Reachable identities
- Multi-hop AssumeRole chains
- Cross-account traversal
- Service-role relationships
- Effective permission calculation

---

Attack Path Engine

Models identity abuse from an adversarial perspective.

Examples include:

- AssumeRole escalation
- PassRole abuse
- Service-role privilege escalation
- Trust policy abuse
- Cross-account lateral movement

---

Detection Engineering

Every offensive technique should have a corresponding defensive detection.

Detection engineering focuses on CloudTrail-observable behavior rather than theoretical indicators.

Examples include:

- Suspicious AssumeRole chains
- Unexpected PassRole usage
- High-risk role assumption sequences
- Identity abuse patterns
- Privilege escalation indicators

---

Research Artifacts

Each research entry contains supporting material beyond source code.

Artifacts may include:

- Threat models
- Attack-path analysis
- Detection logic
- MITRE ATT&CK mapping
- Compliance mapping
- Engineering notes

Research artifacts are stored under:

analysis/

---

Documentation

Project documentation is maintained under:

docs/

Including:

- Architecture
- Threat model
- Compliance framework
- Series overview
- Engineering diagrams

---

Examples

The repository includes realistic examples for testing and experimentation.

Examples include:

- Vulnerable IAM policies
- Trust-policy abuse
- PassRole escalation
- CloudTrail events
- Compliance evidence
- Attack scenarios

---

Technology Stack

- Go
- AWS IAM
- AWS CloudTrail
- Graph-based authorization modeling
- Docker

---

Series Roadmap

Introduction

Introducing Cloud Identity Security Engineering

---

#001

Parsing IAM Policies in Go

Building a parser that preserves IAM semantics for graph construction.

---

#002

Modeling AWS Role Assumption Paths

Representing trust relationships as directed graphs.

---

#003

Detecting Privilege Escalation Opportunities

Building graph traversal algorithms that identify reachable escalation chains.

---

Future Topics

- Resource-based policy abuse
- Service Control Policies (SCP)
- Service-role lateral movement
- Permission boundaries
- Identity federation
- Multi-account graph traversal
- CloudTrail detection automation
- Risk scoring

---

Current Status

This repository is under active development.

Each article in the accompanying series introduces additional functionality while expanding the supporting research and implementation.

The project is intentionally developed incrementally so that every engineering decision, algorithm, and detection strategy can be documented alongside its implementation.

---

License

This project is released under the MIT License.

See the "LICENSE" file for details.