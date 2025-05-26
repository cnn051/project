# Requirements Analysis Phase

## Purpose

The Requirements Analysis phase establishes the security requirements for the Maritime Network Management System (NMS) based on KR GC-44-K and IACS UR E26/E27 standards. This document outlines the processes, methodologies, and outcomes of the security requirements gathering and analysis.

## Security Requirements Identification

### Regulatory Requirements

The Maritime NMS must comply with the following regulatory frameworks:

- Korean Register's "Guidance for Cyber Resilience of Ships and Systems" (GC-44-K, 2024)
- IACS Unified Requirement E26 (Cyber Resilience of Ships)
- IACS Unified Requirement E27 (Cyber Resilience of Onboard Systems and Equipment)
- IMO MSC-FAL.1/Circ.3 - Guidelines on Maritime Cyber Risk Management

### Functional Security Requirements

1. **Asset Inventory (KR GC-44-K, 2.401.1)**
   - Complete tracking of hardware components including name, manufacturer, model, function, interfaces, system software, version, patch level
   - Complete tracking of software components including installed hardware, manufacturer, model, function, version
   - Assignment of assets to security zones and vessels

2. **Security Zones (KR GC-44-K, 2.402.1)**
   - Definition and visualization of logical security zones
   - Zone and Conduit modeling
   - Documentation of security measures for each zone
   - Risk-based zone classification

3. **Access Control (KR GC-44-K, 2.402.4, 3.401)**
   - Role-based access control (administrator, operator, read-only)
   - Implementation of least privilege principle
   - Strong authentication mechanisms
   - Optional multi-factor authentication

4. **Security Monitoring & Logging (KR GC-44-K, 2.403.1, 3.401)**
   - Comprehensive security logs with timestamps
   - Monitoring of all security-relevant events
   - Configurable log storage capacity
   - Alert mechanisms for log storage capacity issues

5. **Data Protection (KR GC-44-K, 3.401)**
   - Integrity verification for sensor data and critical system information
   - Encryption for sensitive data
   - Secure communications for wireless and external connections

6. **Incident Response (KR GC-44-K, 2.404.1)**
   - Alert management system
   - Incident response procedures
   - Fallback to minimum risk state for critical failures

## Threat Modeling

### Methodology

The Maritime NMS threat modeling follows the STRIDE methodology:

- **S**poofing: Impersonation of legitimate users or systems
- **T**ampering: Unauthorized modification of data
- **R**epudiation: Denial of actions performed
- **I**nformation disclosure: Unauthorized access to sensitive information
- **D**enial of service: Disruption of system availability
- **E**levation of privilege: Gaining unauthorized access to system functions

### Key Threats Identified

1. **Maritime-Specific Threats**
   - GPS spoofing affecting vessel positioning data
   - AIS data manipulation
   - Unauthorized access to critical vessel systems
   - Communication link disruption
   - Supply chain compromise of marine equipment

2. **General Cybersecurity Threats**
   - Unauthorized system access (internal and external)
   - Data tampering during transmission
   - SQL injection and other web application attacks
   - Denial of service attacks
   - Malware infection (ransomware, trojans)
   - Social engineering attacks targeting maritime personnel

## Risk Assessment

### Risk Assessment Methodology

The Maritime NMS risk assessment uses a quantitative approach based on:
- Threat likelihood (1-5 scale)
- Impact severity (1-5 scale)
- Risk score = Likelihood × Impact
- Risk categories: Critical (20-25), High (15-19), Medium (10-14), Low (1-9)

### Key Risk Areas

1. **Critical Risks (Score 20-25)**
   - Compromise of authentication systems
   - Unauthorized modification of critical vessel data
   - Database security breaches

2. **High Risks (Score 15-19)**
   - Integrity failures in sensor data collection
   - Inadequate network segmentation
   - Insufficient logging of security events

3. **Medium Risks (Score 10-14)**
   - Session management vulnerabilities
   - Weak password policies
   - Insecure data storage

## Compliance Requirements Mapping

The following table maps KR GC-44-K and IACS requirements to specific Maritime NMS features:

| Requirement ID | Requirement Description | NMS Feature |
|----------------|-------------------------|-------------|
| KR GC-44-K, 2.401.1 | Vessel Asset Inventory | CBS Asset Management |
| KR GC-44-K, 2.402.1 | Security Zones | Security Zone Visualization |
| KR GC-44-K, 2.402.4 | Access Control | Role-based Authentication |
| KR GC-44-K, 2.403.1 | Security Monitoring | Security Logs & Alerts |
| KR GC-44-K, 2.404.1 | Incident Response | Alert Management |
| KR GC-44-K, 3.401 (Items 1-6, 8) | Authentication | User Management |
| KR GC-44-K, 3.401 (Items 13-16) | Logging | Security Log System |
| KR GC-44-K, 3.401 (Item 17) | Integrity | Data Integrity Verification |
| KR GC-44-K, 3.401 (Item 21) | Confidentiality | Data Encryption |
| KR GC-44-K, 3.501 | SDLC | SDLC Documentation |

## Security Requirements Traceability

A comprehensive Security Requirements Traceability Matrix (SRTM) has been developed to ensure all identified security requirements are implemented and verified throughout the SDLC. The SRTM is maintained as a separate document and updated throughout the development lifecycle.

## Approval and Sign-off

This Requirements Analysis document requires review and approval by:
- Security Architect
- Project Manager
- Compliance Officer
- Maritime Cybersecurity Specialist

## Version History

| Version | Date | Changes | Author | Approver |
|---------|------|---------|--------|----------|
| 1.0 | 2023-09-01 | Initial version | Security Team | Project Board |
| 1.1 | 2023-10-15 | Updated for KR GC-44-K 2024 | Security Team | Project Board |
