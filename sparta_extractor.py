#!/usr/bin/env python3
"""
SPARTA (Space Attack Research & Tactic Analysis) Data Extractor and Query System
This script extracts space cyber attack techniques from SPARTA and provides a query interface.
"""

import json
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import os

@dataclass
class SubTechnique:
    id: str
    name: str
    description: str
    parent_id: str

@dataclass
class Technique:
    id: str
    name: str
    description: str
    tactic: str
    tactic_id: str
    sub_techniques: List[SubTechnique]

@dataclass
class Tactic:
    id: str
    name: str
    description: str
    techniques: List[Technique]

# SPARTA Tactics with their IDs and descriptions
TACTICS = [
    {"id": "ST0001", "name": "Reconnaissance", "description": "Threat actor is trying to gather information about the space system."},
    {"id": "ST0002", "name": "Resource Development", "description": "Threat actor is trying to establish resources for future operations."},
    {"id": "ST0003", "name": "Initial Access", "description": "Threat actor is trying to get into the space system."},
    {"id": "ST0004", "name": "Execution", "description": "Threat actor is trying to run malicious code on the spacecraft."},
    {"id": "ST0005", "name": "Persistence", "description": "Threat actor is trying to maintain their foothold/access to command/execute code on the spacecraft."},
    {"id": "ST0006", "name": "Defense Evasion", "description": "Threat actor is trying to avoid being detected."},
    {"id": "ST0007", "name": "Lateral Movement", "description": "Threat actor is trying to move through the space system environment."},
    {"id": "ST0008", "name": "Exfiltration", "description": "Threat actor is trying to steal data from the space system."},
    {"id": "ST0009", "name": "Impact", "description": "Threat actor is trying to manipulate, interrupt, or destroy the space system(s) and/or data."}
]

# Complete SPARTA techniques data extracted from the website
SPARTA_DATA = {
    "ST0001": {  # Reconnaissance
        "techniques": [
            {
                "id": "REC-0001",
                "name": "Gather Spacecraft Design Information",
                "description": "Threat actors may gather information about the victim spacecraft's design that can be used for future campaigns or to help perpetuate other techniques. Information about the spacecraft can include software, firmware, encryption type, purpose, as well as various makes and models of subsystems.",
                "sub_techniques": [
                    {"id": "REC-0001.01", "name": "Software Design", "description": "Threat actors may gather information about the victim spacecraft's internal software that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.02", "name": "Firmware", "description": "Threat actors may gather information about the victim spacecraft's firmware that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.03", "name": "Cryptographic Algorithms", "description": "Threat actors may gather information about any cryptographic algorithms used on the victim spacecraft's that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.04", "name": "Data Bus", "description": "Threat actors may gather information about the data bus used within the victim spacecraft that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.05", "name": "Thermal Control System", "description": "Threat actors may gather information about the thermal control system used with the victim spacecraft that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.06", "name": "Maneuver & Control", "description": "Threat actors may gather information about the station-keeping control systems within the victim spacecraft that can be used for future campaigns or to help perpetuate other techniques."},
                    {"id": "REC-0001.07", "name": "Payload", "description": "Threat actors may gather information about the type(s) of payloads hosted on the victim spacecraft."},
                    {"id": "REC-0001.08", "name": "Power", "description": "Threat actors may gather information about the power system used within the victim spacecraft."},
                    {"id": "REC-0001.09", "name": "Fault Management", "description": "Threat actors may gather information about any fault management that may be present on the victim spacecraft."}
                ]
            },
            {
                "id": "REC-0002",
                "name": "Gather Spacecraft Descriptors",
                "description": "Threat actors may gather information about the victim spacecraft's descriptors that can be used for future campaigns or to help perpetuate other techniques.",
                "sub_techniques": [
                    {"id": "REC-0002.01", "name": "Identifiers", "description": "Threat actors may gather information about the victim spacecraft's identity attributes."},
                    {"id": "REC-0002.02", "name": "Organization", "description": "Threat actors may gather information about the victim spacecraft's associated organization(s)."},
                    {"id": "REC-0002.03", "name": "Operations", "description": "Threat actors may gather information about the victim spacecraft's operations."}
                ]
            },
            {
                "id": "REC-0003",
                "name": "Gather Spacecraft Communications Information",
                "description": "Threat actors may obtain information on the victim spacecraft's communication channels in order to determine specific commands, protocols, and types.",
                "sub_techniques": [
                    {"id": "REC-0003.01", "name": "Communications Equipment", "description": "Threat actors may gather information regarding the communications equipment and its configuration."},
                    {"id": "REC-0003.02", "name": "Commanding Details", "description": "Threat actors may gather information regarding the commanding approach."},
                    {"id": "REC-0003.03", "name": "Mission-Specific Channel Scanning", "description": "Threat actors may seek knowledge about mission-specific communication channels."},
                    {"id": "REC-0003.04", "name": "Valid Credentials", "description": "Threat actors may seek out valid credentials which can be utilized to facilitate several tactics."}
                ]
            },
            {
                "id": "REC-0004",
                "name": "Gather Launch Information",
                "description": "Threat actors may gather the launch date and time, location of the launch, organizations involved, launch vehicle, etc.",
                "sub_techniques": [
                    {"id": "REC-0004.01", "name": "Flight Termination", "description": "Threat actor may obtain information regarding the vehicle's flight termination system."}
                ]
            },
            {
                "id": "REC-0005",
                "name": "Eavesdropping",
                "description": "Threat actors may seek to capture network communications throughout the ground station and radio frequency (RF) communication used for uplink and downlink communications.",
                "sub_techniques": [
                    {"id": "REC-0005.01", "name": "Uplink Intercept Eavesdropping", "description": "Threat actors may capture the RF communications as it pertains to the uplink to the victim spacecraft."},
                    {"id": "REC-0005.02", "name": "Downlink Intercept", "description": "Threat actors may capture the RF communications as it pertains to the downlink of the victim spacecraft."},
                    {"id": "REC-0005.03", "name": "Proximity Operations", "description": "Threat actors may capture signals and/or network communications as they travel on-board the vehicle."},
                    {"id": "REC-0005.04", "name": "Active Scanning (RF/Optical)", "description": "Threat actors may interfere with the link by actively transmitting packets to activate the transmitter."}
                ]
            },
            {
                "id": "REC-0006",
                "name": "Gather FSW Development Information",
                "description": "Threat actors may obtain information regarding the flight software (FSW) development environment for the victim spacecraft.",
                "sub_techniques": [
                    {"id": "REC-0006.01", "name": "Development Environment", "description": "Threat actors may gather information regarding the development environment for the victim spacecraft's FSW."},
                    {"id": "REC-0006.02", "name": "Security Testing Tools", "description": "Threat actors may gather information regarding how a victim spacecraft is tested."}
                ]
            },
            {
                "id": "REC-0007",
                "name": "Monitor for Safe-Mode Indicators",
                "description": "Threat actors may gather information regarding safe-mode indicators on the victim spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "REC-0008",
                "name": "Gather Supply Chain Information",
                "description": "Threat actors may gather information about a mission's supply chain or product delivery mechanisms.",
                "sub_techniques": [
                    {"id": "REC-0008.01", "name": "Hardware Recon", "description": "Threat actors may gather information to facilitate a future hardware supply chain attack."},
                    {"id": "REC-0008.02", "name": "Software Recon", "description": "Threat actors may gather information relating to the mission's software supply chain."},
                    {"id": "REC-0008.03", "name": "Known Vulnerabilities", "description": "Threat actors may gather information about vulnerabilities that can be used for future campaigns."},
                    {"id": "REC-0008.04", "name": "Business Relationships", "description": "Adversaries may gather information about the victim's business relationships."}
                ]
            },
            {
                "id": "REC-0009",
                "name": "Gather Mission Information",
                "description": "Threat actors may initially seek to gain an understanding of a target mission by gathering information commonly captured in a Concept of Operations.",
                "sub_techniques": []
            }
        ]
    },
    "ST0002": {  # Resource Development
        "techniques": [
            {
                "id": "RD-0001",
                "name": "Acquire Infrastructure",
                "description": "Threat actors may buy, lease, or rent infrastructure that can be used for future campaigns or to perpetuate other techniques.",
                "sub_techniques": [
                    {"id": "RD-0001.01", "name": "Ground Station Equipment", "description": "Threat actors will likely need to acquire ground station equipment to establish ground-to-space communications."},
                    {"id": "RD-0001.02", "name": "Commercial Ground Station Services", "description": "Threat actors may buy or rent commercial ground station services."},
                    {"id": "RD-0001.03", "name": "Spacecraft", "description": "Threat actors may acquire their own spacecraft that has the capability to maneuver within close proximity to a target."},
                    {"id": "RD-0001.04", "name": "Launch Facility", "description": "Threat actors may need to acquire a launch facility for launching spacecraft and rockets into space."}
                ]
            },
            {
                "id": "RD-0002",
                "name": "Compromise Infrastructure",
                "description": "Threat actors may compromise third-party infrastructure that can be used for future campaigns.",
                "sub_techniques": [
                    {"id": "RD-0002.01", "name": "Mission-Operated Ground System", "description": "Threat actors may compromise mission owned/operated ground systems."},
                    {"id": "RD-0002.02", "name": "3rd Party Ground System", "description": "Threat actors may compromise access to third-party ground systems."},
                    {"id": "RD-0002.03", "name": "3rd-Party Spacecraft", "description": "Threat actors may compromise a 3rd-party spacecraft."}
                ]
            },
            {
                "id": "RD-0003",
                "name": "Obtain Cyber Capabilities",
                "description": "Threat actors may buy and/or steal cyber capabilities that can be used for future campaigns.",
                "sub_techniques": [
                    {"id": "RD-0003.01", "name": "Exploit/Payload", "description": "Threat actors may buy, steal, or download exploits and payloads."},
                    {"id": "RD-0003.02", "name": "Cryptographic Keys", "description": "Threat actors may obtain encryption keys for commanding the target spacecraft."}
                ]
            },
            {
                "id": "RD-0004",
                "name": "Stage Capabilities",
                "description": "Threat actors may upload, install, or otherwise set up capabilities for future campaigns.",
                "sub_techniques": [
                    {"id": "RD-0004.01", "name": "Identify/Select Delivery Mechanism", "description": "Threat actors may identify, select, and prepare a delivery mechanism."},
                    {"id": "RD-0004.02", "name": "Upload Exploit/Payload", "description": "Threat actors may upload exploits and payloads to a third-party infrastructure."}
                ]
            },
            {
                "id": "RD-0005",
                "name": "Obtain Non-Cyber Capabilities",
                "description": "Threat actors may obtain non-cyber capabilities, primarily physical counterspace weapons or systems.",
                "sub_techniques": [
                    {"id": "RD-0005.01", "name": "Launch Services", "description": "Threat actors may acquire launch capabilities."},
                    {"id": "RD-0005.02", "name": "Non-Kinetic Physical ASAT", "description": "A non-kinetic physical ASAT attack is when a satellite is physically damaged without any direct contact."},
                    {"id": "RD-0005.03", "name": "Kinetic Physical ASAT", "description": "Kinetic physical ASAT attacks attempt to damage or destroy space- or land-based space assets."},
                    {"id": "RD-0005.04", "name": "Electronic ASAT", "description": "Electronic ASAT attacks target the means by which space systems transmit and receive data."}
                ]
            }
        ]
    },
    "ST0003": {  # Initial Access
        "techniques": [
            {
                "id": "IA-0001",
                "name": "Compromise Supply Chain",
                "description": "Threat actors may manipulate or compromise products or product delivery mechanisms before the customer receives them.",
                "sub_techniques": [
                    {"id": "IA-0001.01", "name": "Software Dependencies & Development Tools", "description": "Threat actors may manipulate software dependencies and/or development tools."},
                    {"id": "IA-0001.02", "name": "Software Supply Chain", "description": "Threat actors may manipulate software binaries and applications prior to customer receipt."},
                    {"id": "IA-0001.03", "name": "Hardware Supply Chain", "description": "Threat actors may manipulate hardware components in the victim spacecraft."}
                ]
            },
            {
                "id": "IA-0002",
                "name": "Compromise Software Defined Radio",
                "description": "Threat actors may target software defined radios due to their software nature to establish C2 channels.",
                "sub_techniques": []
            },
            {
                "id": "IA-0003",
                "name": "Crosslink via Compromised Neighbor",
                "description": "Threat actors may compromise a victim spacecraft via the crosslink communications of a neighboring spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "IA-0004",
                "name": "Secondary/Backup Communication Channel",
                "description": "Threat actors may compromise alternative communication pathways which may not be as protected.",
                "sub_techniques": [
                    {"id": "IA-0004.01", "name": "Ground Station", "description": "Threat actors may establish a foothold within the backup ground/mission operations center."},
                    {"id": "IA-0004.02", "name": "Receiver", "description": "Threat actors may target the backup/secondary receiver on the spacecraft."}
                ]
            },
            {
                "id": "IA-0005",
                "name": "Rendezvous & Proximity Operations",
                "description": "Threat actors may perform a space rendezvous to approach very close distance to a target spacecraft.",
                "sub_techniques": [
                    {"id": "IA-0005.01", "name": "Compromise Emanations", "description": "Threat actors in close proximity may intercept and analyze electromagnetic radiation."},
                    {"id": "IA-0005.02", "name": "Docked Vehicle / OSAM", "description": "Threat actors may leverage docking vehicles to laterally move into a target spacecraft."},
                    {"id": "IA-0005.03", "name": "Proximity Grappling", "description": "Threat actors may grapple target spacecraft once it has established the appropriate space rendezvous."}
                ]
            },
            {
                "id": "IA-0006",
                "name": "Compromise Hosted Payload",
                "description": "Threat actors may compromise the target spacecraft hosted payload to initially access and/or persist within the system.",
                "sub_techniques": []
            },
            {
                "id": "IA-0007",
                "name": "Compromise Ground System",
                "description": "Threat actors may initially compromise the ground system in order to access the target spacecraft.",
                "sub_techniques": [
                    {"id": "IA-0007.01", "name": "Compromise On-Orbit Update", "description": "Threat actors may manipulate and modify on-orbit updates before they are sent."},
                    {"id": "IA-0007.02", "name": "Malicious Commanding via Valid GS", "description": "Threat actors may compromise target owned ground systems components."}
                ]
            },
            {
                "id": "IA-0008",
                "name": "Rogue External Entity",
                "description": "Threat actors may gain access to a victim spacecraft through the use of a rogue external entity.",
                "sub_techniques": [
                    {"id": "IA-0008.01", "name": "Rogue Ground Station", "description": "Threat actors may gain access through the use of a rogue ground system."},
                    {"id": "IA-0008.02", "name": "Rogue Spacecraft", "description": "Threat actors may gain access using their own spacecraft."},
                    {"id": "IA-0008.03", "name": "ASAT/Counterspace Weapon", "description": "Threat actors may utilize counterspace platforms to access/impact spacecraft."}
                ]
            },
            {
                "id": "IA-0009",
                "name": "Trusted Relationship",
                "description": "Access through trusted third-party relationship exploits an existing connection.",
                "sub_techniques": [
                    {"id": "IA-0009.01", "name": "Mission Collaborator", "description": "Threat actors may seek to exploit mission partners."},
                    {"id": "IA-0009.02", "name": "Vendor", "description": "Threat actors may target the trust between vendors and the target spacecraft."},
                    {"id": "IA-0009.03", "name": "User Segment", "description": "Threat actors can target the user segment in an effort to laterally move."}
                ]
            },
            {
                "id": "IA-0010",
                "name": "Unauthorized Access During Safe-Mode",
                "description": "Threat actors may target a spacecraft in safe mode to establish initial access.",
                "sub_techniques": []
            },
            {
                "id": "IA-0011",
                "name": "Auxiliary Device Compromise",
                "description": "Threat actors may exploit the auxiliary/peripheral devices that get plugged into spacecrafts.",
                "sub_techniques": []
            },
            {
                "id": "IA-0012",
                "name": "Assembly, Test, and Launch Operation Compromise",
                "description": "Threat actors may target the spacecraft hardware and/or software while at ATLO.",
                "sub_techniques": []
            },
            {
                "id": "IA-0013",
                "name": "Compromise Host Spacecraft",
                "description": "The host space vehicle can serve as an initial access vector to compromise the payload.",
                "sub_techniques": []
            }
        ]
    },
    "ST0004": {  # Execution
        "techniques": [
            {
                "id": "EX-0001",
                "name": "Replay",
                "description": "Replay attacks involve threat actors recording previously recorded data streams and then resending them.",
                "sub_techniques": [
                    {"id": "EX-0001.01", "name": "Command Packets", "description": "Threat actors may interact with the victim spacecraft by replaying captured commands."},
                    {"id": "EX-0001.02", "name": "Bus Traffic Replay", "description": "Threat actors may abuse internal commanding to replay bus traffic."}
                ]
            },
            {
                "id": "EX-0002",
                "name": "Position, Navigation, and Timing (PNT) Geofencing",
                "description": "Threat actors may leverage spacecraft mobility for location-based malware triggers.",
                "sub_techniques": []
            },
            {
                "id": "EX-0003",
                "name": "Modify Authentication Process",
                "description": "Threat actors may modify the internal authentication process of the victim spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "EX-0004",
                "name": "Compromise Boot Memory",
                "description": "Threat actors may manipulate boot memory to execute malicious code.",
                "sub_techniques": []
            },
            {
                "id": "EX-0005",
                "name": "Exploit Hardware/Firmware Corruption",
                "description": "Threat actors can target the underlying hardware and/or firmware.",
                "sub_techniques": [
                    {"id": "EX-0005.01", "name": "Design Flaws", "description": "Threat actors may target design features/flaws with the hardware design."},
                    {"id": "EX-0005.02", "name": "Malicious Use of Hardware Commands", "description": "Threat actors may utilize various hardware commands for malicious activities."}
                ]
            },
            {
                "id": "EX-0006",
                "name": "Disable/Bypass Encryption",
                "description": "Threat actors may bypass or disable the encryption mechanism onboard the victim spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "EX-0007",
                "name": "Trigger Single Event Upset",
                "description": "Threat actors may utilize techniques to create a single-event upset (SEU).",
                "sub_techniques": []
            },
            {
                "id": "EX-0008",
                "name": "Time Synchronized Execution",
                "description": "Threat actors may develop payloads to be executed at a specific time.",
                "sub_techniques": [
                    {"id": "EX-0008.01", "name": "Absolute Time Sequences", "description": "Event is triggered at specific date/time."},
                    {"id": "EX-0008.02", "name": "Relative Time Sequences", "description": "Event is triggered in relation to some other event."}
                ]
            },
            {
                "id": "EX-0009",
                "name": "Exploit Code Flaws",
                "description": "Threats actors may identify and exploit flaws or weaknesses within the software.",
                "sub_techniques": [
                    {"id": "EX-0009.01", "name": "Flight Software", "description": "Threat actors may abuse flight software code flaws."},
                    {"id": "EX-0009.02", "name": "Operating System", "description": "Threat actors may exploit flaws in the operating system code."},
                    {"id": "EX-0009.03", "name": "Known Vulnerability (COTS/FOSS)", "description": "Threat actors may exploit known flaws in commercial or open source software."}
                ]
            },
            {
                "id": "EX-0010",
                "name": "Malicious Code",
                "description": "Threat actors may execute malicious code on the victim spacecraft.",
                "sub_techniques": [
                    {"id": "EX-0010.01", "name": "Ransomware", "description": "Threat actors may encrypt spacecraft data to interrupt availability."},
                    {"id": "EX-0010.02", "name": "Wiper Malware", "description": "Threat actors may deploy wiper malware to destroy data."},
                    {"id": "EX-0010.03", "name": "Rootkit", "description": "Rootkits hide the existence of malware by intercepting OS API calls."},
                    {"id": "EX-0010.04", "name": "Bootkit", "description": "Bootkits persist on systems and evade detection at boot level."}
                ]
            },
            {
                "id": "EX-0011",
                "name": "Exploit Reduced Protections During Safe-Mode",
                "description": "Threat actors may exploit safe mode to issue malicious commands.",
                "sub_techniques": []
            },
            {
                "id": "EX-0012",
                "name": "Modify On-Board Values",
                "description": "Threat actors may modify onboard values that the victim spacecraft relies on.",
                "sub_techniques": [
                    {"id": "EX-0012.01", "name": "Registers", "description": "Threat actors may target the internal registers."},
                    {"id": "EX-0012.02", "name": "Internal Routing Tables", "description": "Threat actors may modify the internal routing tables."},
                    {"id": "EX-0012.03", "name": "Memory Write/Loads", "description": "Threat actors may utilize direct memory access."},
                    {"id": "EX-0012.04", "name": "App/Subscriber Tables", "description": "Threat actors may target the application or subscriber table."},
                    {"id": "EX-0012.05", "name": "Scheduling Algorithm", "description": "Threat actors may target scheduling features."},
                    {"id": "EX-0012.06", "name": "Science/Payload Data", "description": "Threat actors may target the internal payload data."},
                    {"id": "EX-0012.07", "name": "Propulsion Subsystem", "description": "Threat actors may target the propulsion subsystem values."},
                    {"id": "EX-0012.08", "name": "Attitude Determination & Control Subsystem", "description": "Threat actors may target the ADCS values."},
                    {"id": "EX-0012.09", "name": "Electrical Power Subsystem", "description": "Threat actors may target power subsystem."},
                    {"id": "EX-0012.10", "name": "Command & Data Handling Subsystem", "description": "Threat actors may target C&DH values."},
                    {"id": "EX-0012.11", "name": "Watchdog Timer (WDT)", "description": "Threat actors may manipulate the WDT."},
                    {"id": "EX-0012.12", "name": "System Clock", "description": "Adversary may alter the system clock."},
                    {"id": "EX-0012.13", "name": "Poison AI/ML Training Data", "description": "Threat actors may perform data poisoning attacks."}
                ]
            },
            {
                "id": "EX-0013",
                "name": "Flooding",
                "description": "Threat actors use flooding attacks to disrupt communications.",
                "sub_techniques": [
                    {"id": "EX-0013.01", "name": "Valid Commands", "description": "Threat actors may utilize valid commanding as a flooding mechanism."},
                    {"id": "EX-0013.02", "name": "Erroneous Input", "description": "Threat actors inject noise/data/signals into the target channel."}
                ]
            },
            {
                "id": "EX-0014",
                "name": "Spoofing",
                "description": "Threat actors may attempt to spoof various sensor and controller data.",
                "sub_techniques": [
                    {"id": "EX-0014.01", "name": "Time Spoof", "description": "Threat actors may target the internal timers and spoof their data."},
                    {"id": "EX-0014.02", "name": "Bus Traffic Spoofing", "description": "Threat actors may target the main bus and spoof data."},
                    {"id": "EX-0014.03", "name": "Sensor Data", "description": "Threat actors may target sensor data."},
                    {"id": "EX-0014.04", "name": "PNT Spoofing", "description": "Threat actors may spoof GNSS signals."},
                    {"id": "EX-0014.05", "name": "Ballistic Missile Spoof", "description": "Threat actors may launch decoys to spoof missile signatures."}
                ]
            },
            {
                "id": "EX-0015",
                "name": "Side-Channel Attack",
                "description": "Threat actors may use side-channel attacks to gather information or influence program execution.",
                "sub_techniques": []
            },
            {
                "id": "EX-0016",
                "name": "Jamming",
                "description": "Jamming is an electronic attack that uses RF signals to interfere with communications.",
                "sub_techniques": [
                    {"id": "EX-0016.01", "name": "Uplink Jamming", "description": "An uplink jammer interferes with signals going up to a satellite."},
                    {"id": "EX-0016.02", "name": "Downlink Jamming", "description": "Downlink jammers target the users of a satellite."},
                    {"id": "EX-0016.03", "name": "PNT Jamming", "description": "Threat actors may jam GNSS signals."}
                ]
            },
            {
                "id": "EX-0017",
                "name": "Kinetic Physical Attack",
                "description": "Kinetic physical attacks attempt to damage or destroy space assets.",
                "sub_techniques": [
                    {"id": "EX-0017.01", "name": "Direct Ascent ASAT", "description": "A missile launching from Earth to damage or destroy a satellite."},
                    {"id": "EX-0017.02", "name": "Co-Orbital ASAT", "description": "Another satellite in orbit is used to attack."}
                ]
            },
            {
                "id": "EX-0018",
                "name": "Non-Kinetic Physical Attack",
                "description": "A satellite is physically damaged without any direct contact.",
                "sub_techniques": [
                    {"id": "EX-0018.01", "name": "Electromagnetic Pulse (EMP)", "description": "An EMP is an indiscriminate form of attack in space."},
                    {"id": "EX-0018.02", "name": "High-Powered Laser", "description": "A high-powered laser can damage critical satellite components."},
                    {"id": "EX-0018.03", "name": "High-Powered Microwave", "description": "HPM weapons can disrupt or destroy satellite electronics."}
                ]
            }
        ]
    },
    "ST0005": {  # Persistence
        "techniques": [
            {
                "id": "PER-0001",
                "name": "Memory Compromise",
                "description": "Threat actors may manipulate memory for malicious code to remain on the victim spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "PER-0002",
                "name": "Backdoor",
                "description": "Threat actors may find and target various backdoors within the victim spacecraft.",
                "sub_techniques": [
                    {"id": "PER-0002.01", "name": "Hardware Backdoor", "description": "Threat actors may find and target various hardware backdoors."},
                    {"id": "PER-0002.02", "name": "Software Backdoor", "description": "Threat actors may inject code to create their own backdoor."}
                ]
            },
            {
                "id": "PER-0003",
                "name": "Ground System Presence",
                "description": "Threat actors may compromise target owned ground systems for persistent access.",
                "sub_techniques": []
            },
            {
                "id": "PER-0004",
                "name": "Replace Cryptographic Keys",
                "description": "Threat actors may attempt to fully replace the cryptographic keys on the spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "PER-0005",
                "name": "Credentialed Persistence",
                "description": "Threat actors may acquire or leverage valid credentials to maintain persistent access.",
                "sub_techniques": []
            }
        ]
    },
    "ST0006": {  # Defense Evasion
        "techniques": [
            {
                "id": "DE-0001",
                "name": "Disable Fault Management",
                "description": "Threat actors may disable fault management within the victim spacecraft.",
                "sub_techniques": []
            },
            {
                "id": "DE-0002",
                "name": "Disrupt or Deceive Downlink",
                "description": "Threat actors may target ground-side telemetry reception to disrupt visibility.",
                "sub_techniques": [
                    {"id": "DE-0002.01", "name": "Inhibit Ground System Functionality", "description": "Threat actors may utilize access to inhibit ground system telemetry processing."},
                    {"id": "DE-0002.02", "name": "Jam Link Signal", "description": "Threat actors may jam the downlink signal."},
                    {"id": "DE-0002.03", "name": "Inhibit Spacecraft Functionality", "description": "Threat actors may shut down spacecraft's on-board processes."}
                ]
            },
            {
                "id": "DE-0003",
                "name": "On-Board Values Obfuscation",
                "description": "Threat actors may target various onboard values to hide malicious activity.",
                "sub_techniques": [
                    {"id": "DE-0003.01", "name": "Vehicle Command Counter (VCC)", "description": "Threat actors may modify the VCC."},
                    {"id": "DE-0003.02", "name": "Rejected Command Counter", "description": "Threat actors may modify the Rejected Command Counter."},
                    {"id": "DE-0003.03", "name": "Command Receiver On/Off Mode", "description": "Threat actors may modify the command receiver mode."},
                    {"id": "DE-0003.04", "name": "Command Receivers Received Signal Strength", "description": "Threat actors may target signal parameters."},
                    {"id": "DE-0003.05", "name": "Command Receiver Lock Modes", "description": "Threat actors can attempt command lock."},
                    {"id": "DE-0003.06", "name": "Telemetry Downlink Modes", "description": "Threat actors may target downlink modes."},
                    {"id": "DE-0003.07", "name": "Cryptographic Modes", "description": "Threat actors may modify cryptographic modes."},
                    {"id": "DE-0003.08", "name": "Received Commands", "description": "Threat actors may manipulate stored command logs."},
                    {"id": "DE-0003.09", "name": "System Clock for Evasion", "description": "Adversary may alter the system clock."},
                    {"id": "DE-0003.10", "name": "GPS Ephemeris", "description": "Hostile actor could spoof GPS signals."},
                    {"id": "DE-0003.11", "name": "Watchdog Timer (WDT) for Evasion", "description": "Threat actors may manipulate the WDT."},
                    {"id": "DE-0003.12", "name": "Poison AI/ML Training for Evasion", "description": "Threat actors may perform data poisoning."}
                ]
            },
            {
                "id": "DE-0004",
                "name": "Masquerading",
                "description": "Threat actors may gain access by masquerading as an authorized entity.",
                "sub_techniques": []
            },
            {
                "id": "DE-0005",
                "name": "Subvert Protections via Safe-Mode",
                "description": "Threat actors may exploit safe mode to evade security controls.",
                "sub_techniques": []
            },
            {
                "id": "DE-0006",
                "name": "Modify Whitelist",
                "description": "Threat actors may target whitelists to execute/hide malicious processes.",
                "sub_techniques": []
            },
            {
                "id": "DE-0007",
                "name": "Evasion via Rootkit",
                "description": "Rootkits hide the existence of malware by intercepting OS API calls.",
                "sub_techniques": []
            },
            {
                "id": "DE-0008",
                "name": "Evasion via Bootkit",
                "description": "Bootkits persist on systems and evade detection.",
                "sub_techniques": []
            },
            {
                "id": "DE-0009",
                "name": "Camouflage, Concealment, and Decoys (CCD)",
                "description": "This technique deals with physical aspects of CCD utilized by threat actors.",
                "sub_techniques": [
                    {"id": "DE-0009.01", "name": "Debris Field", "description": "Threat actors may hide spacecraft within debris fields."},
                    {"id": "DE-0009.02", "name": "Space Weather", "description": "Threat actors may take advantage of solar activity."},
                    {"id": "DE-0009.03", "name": "Trigger Premature Intercept", "description": "Threat actors may utilize decoy technology."},
                    {"id": "DE-0009.04", "name": "Targeted Deception of Onboard SSA/SDA Sensors", "description": "Threat actors may degrade or manipulate SDA sensors."},
                    {"id": "DE-0009.05", "name": "Corruption or Overload of Ground-Based SDA Systems", "description": "Threat actors may target ground-based SDA systems."}
                ]
            },
            {
                "id": "DE-0010",
                "name": "Overflow Audit Log",
                "description": "Threat actors may exploit limited logging capacity to conceal activity.",
                "sub_techniques": []
            },
            {
                "id": "DE-0011",
                "name": "Credentialed Evasion",
                "description": "Threat actors may leverage valid credentials to evade detection.",
                "sub_techniques": []
            },
            {
                "id": "DE-0012",
                "name": "Component Collusion",
                "description": "Two or more compromised components operate in coordination to conceal malicious activity.",
                "sub_techniques": []
            }
        ]
    },
    "ST0007": {  # Lateral Movement
        "techniques": [
            {
                "id": "LM-0001",
                "name": "Hosted Payload",
                "description": "Threat actors may use the hosted payload to gain access to other subsystems.",
                "sub_techniques": []
            },
            {
                "id": "LM-0002",
                "name": "Exploit Lack of Bus Segregation",
                "description": "Threat actors may exploit on-board flat architecture for lateral movement.",
                "sub_techniques": []
            },
            {
                "id": "LM-0003",
                "name": "Constellation Hopping via Crosslink",
                "description": "Threat actors may command another neighboring spacecraft via crosslink.",
                "sub_techniques": []
            },
            {
                "id": "LM-0004",
                "name": "Visiting Vehicle Interface(s)",
                "description": "Threat actors may move from one spacecraft to another through visiting vehicle interfaces.",
                "sub_techniques": []
            },
            {
                "id": "LM-0005",
                "name": "Virtualization Escape",
                "description": "Threat actors can use open ports between partitions to overcome hypervisor's protection.",
                "sub_techniques": []
            },
            {
                "id": "LM-0006",
                "name": "Launch Vehicle Interface",
                "description": "Threat actors may exploit interfaces between launch vehicles and payloads.",
                "sub_techniques": [
                    {"id": "LM-0006.01", "name": "Rideshare Payload", "description": "Threat actors may move laterally between co-located payloads."}
                ]
            },
            {
                "id": "LM-0007",
                "name": "Credentialed Traversal",
                "description": "Threat actors may leverage valid credentials to traverse across spacecraft subsystems.",
                "sub_techniques": []
            }
        ]
    },
    "ST0008": {  # Exfiltration
        "techniques": [
            {
                "id": "EXF-0001",
                "name": "Replay",
                "description": "Threat actors may exfiltrate data by replaying commands and capturing telemetry.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0002",
                "name": "Side-Channel Exfiltration",
                "description": "Threat actors may use side-channel attacks to gather information.",
                "sub_techniques": [
                    {"id": "EXF-0002.01", "name": "Power Analysis Attacks", "description": "Threat actors can analyze power consumption to exfiltrate information."},
                    {"id": "EXF-0002.02", "name": "Electromagnetic Leakage Attacks", "description": "Threat actors can leverage electromagnetic emanations."},
                    {"id": "EXF-0002.03", "name": "Traffic Analysis Attacks", "description": "Threat actors use traffic analysis to gather topological information."},
                    {"id": "EXF-0002.04", "name": "Timing Attacks", "description": "Threat actors can leverage timing attacks."},
                    {"id": "EXF-0002.05", "name": "Thermal Imaging attacks", "description": "Threat actors can leverage thermal imaging attacks."}
                ]
            },
            {
                "id": "EXF-0003",
                "name": "Signal Interception",
                "description": "Threat actors may seek to capture network communications.",
                "sub_techniques": [
                    {"id": "EXF-0003.01", "name": "Uplink Exfiltration", "description": "Threat actors may target the uplink connection."},
                    {"id": "EXF-0003.02", "name": "Downlink Exfiltration", "description": "Threat actors may target the downlink connection."}
                ]
            },
            {
                "id": "EXF-0004",
                "name": "Out-of-Band Communications Link",
                "description": "Threat actors may attempt to exfiltrate data via out-of-band communication channels.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0005",
                "name": "Proximity Operations",
                "description": "Threat actors may leverage lack of emission security to exfiltrate information.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0006",
                "name": "Modify Communications Configuration",
                "description": "Threat actors can manipulate communications equipment to exfiltrate data.",
                "sub_techniques": [
                    {"id": "EXF-0006.01", "name": "Software Defined Radio", "description": "Threat actors may target SDRs to setup exfiltration channels."},
                    {"id": "EXF-0006.02", "name": "Transponder", "description": "Threat actors may change the transponder configuration."}
                ]
            },
            {
                "id": "EXF-0007",
                "name": "Compromised Ground System",
                "description": "Threat actors may compromise target owned ground systems.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0008",
                "name": "Compromised Developer Site",
                "description": "Threat actors may compromise development environments.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0009",
                "name": "Compromised Partner Site",
                "description": "Threat actors may compromise access to partner sites.",
                "sub_techniques": []
            },
            {
                "id": "EXF-0010",
                "name": "Payload Communication Channel",
                "description": "Threat actors can deploy malicious software on the payload for data exfiltration.",
                "sub_techniques": []
            }
        ]
    },
    "ST0009": {  # Impact
        "techniques": [
            {
                "id": "IMP-0001",
                "name": "Deception (or Misdirection)",
                "description": "Measures designed to mislead an adversary by manipulation, distortion, or falsification of evidence.",
                "sub_techniques": []
            },
            {
                "id": "IMP-0002",
                "name": "Disruption",
                "description": "Measures designed to temporarily impair the use or access to a system for a period of time.",
                "sub_techniques": []
            },
            {
                "id": "IMP-0003",
                "name": "Denial",
                "description": "Measures designed to temporarily eliminate the use, access, or operation of a system.",
                "sub_techniques": []
            },
            {
                "id": "IMP-0004",
                "name": "Degradation",
                "description": "Measures designed to permanently impair the use of a system.",
                "sub_techniques": []
            },
            {
                "id": "IMP-0005",
                "name": "Destruction",
                "description": "Measures designed to permanently eliminate the use of a system.",
                "sub_techniques": []
            },
            {
                "id": "IMP-0006",
                "name": "Theft",
                "description": "Threat actors may attempt to steal the data being gathered, processed, and sent from the spacecraft.",
                "sub_techniques": []
            }
        ]
    }
}


def build_database() -> List[Dict]:
    """Build a flat database of all techniques and sub-techniques."""
    database = []
    
    for tactic_info in TACTICS:
        tactic_id = tactic_info["id"]
        tactic_name = tactic_info["name"]
        tactic_desc = tactic_info["description"]
        
        if tactic_id in SPARTA_DATA:
            for technique in SPARTA_DATA[tactic_id]["techniques"]:
                # Add main technique
                entry = {
                    "type": "technique",
                    "id": technique["id"],
                    "name": technique["name"],
                    "description": technique["description"],
                    "tactic": tactic_name,
                    "tactic_id": tactic_id,
                    "tactic_description": tactic_desc,
                    "parent_id": None,
                    "full_text": f"{technique['name']} {technique['description']} {tactic_name}"
                }
                database.append(entry)
                
                # Add sub-techniques
                for sub in technique.get("sub_techniques", []):
                    sub_entry = {
                        "type": "sub_technique",
                        "id": sub["id"],
                        "name": sub["name"],
                        "description": sub["description"],
                        "tactic": tactic_name,
                        "tactic_id": tactic_id,
                        "tactic_description": tactic_desc,
                        "parent_id": technique["id"],
                        "parent_name": technique["name"],
                        "full_text": f"{sub['name']} {sub['description']} {technique['name']} {tactic_name}"
                    }
                    database.append(sub_entry)
    
    return database


def save_database(database: List[Dict], filename: str = "sparta_database.json"):
    """Save the database to a JSON file."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(database, f, indent=2, ensure_ascii=False)
    print(f"Database saved to {filename}")
    print(f"Total entries: {len(database)}")


def load_database(filename: str = "sparta_database.json") -> List[Dict]:
    """Load the database from a JSON file."""
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)


def search_techniques(database: List[Dict], query: str, top_k: int = 5) -> List[Dict]:
    """
    Simple keyword-based search for techniques.
    Returns the most relevant techniques based on keyword matching.
    """
    query_lower = query.lower()
    query_words = set(query_lower.split())
    
    scored_results = []
    for entry in database:
        full_text_lower = entry["full_text"].lower()
        
        # Score based on different factors
        score = 0
        
        # Exact phrase match in name
        if query_lower in entry["name"].lower():
            score += 100
        
        # Exact phrase match in description
        if query_lower in entry["description"].lower():
            score += 50
        
        # Word overlap
        entry_words = set(full_text_lower.split())
        overlap = query_words & entry_words
        score += len(overlap) * 10
        
        # Partial matches
        for word in query_words:
            if word in full_text_lower:
                score += 5
        
        if score > 0:
            scored_results.append((score, entry))
    
    # Sort by score descending
    scored_results.sort(key=lambda x: x[0], reverse=True)
    
    return [entry for _, entry in scored_results[:top_k]]


def print_result(entry: Dict):
    """Print a search result in a formatted way."""
    print(f"\n{'='*80}")
    print(f"ID: {entry['id']}")
    print(f"Name: {entry['name']}")
    print(f"Type: {entry['type'].replace('_', ' ').title()}")
    print(f"Tactic: {entry['tactic']} ({entry['tactic_id']})")
    if entry.get('parent_id'):
        print(f"Parent Technique: {entry.get('parent_name')} ({entry['parent_id']})")
    print(f"\nDescription:\n{entry['description']}")
    print(f"{'='*80}")


def interactive_query(database: List[Dict]):
    """Interactive query interface."""
    print("\n" + "="*80)
    print("SPARTA Space Security Query System")
    print("="*80)
    print("Enter your query about space security threats (or 'quit' to exit)")
    
    while True:
        print("\n")
        query = input("Query: ").strip()
        
        if query.lower() in ['quit', 'exit', 'q']:
            print("Goodbye!")
            break
        
        if not query:
            continue
        
        results = search_techniques(database, query, top_k=5)
        
        if results:
            print(f"\nFound {len(results)} relevant technique(s):")
            for result in results:
                print_result(result)
        else:
            print("\nNo matching techniques found. Try different keywords.")


def get_statistics(database: List[Dict]) -> Dict:
    """Get statistics about the database."""
    stats = {
        "total_entries": len(database),
        "techniques": sum(1 for e in database if e["type"] == "technique"),
        "sub_techniques": sum(1 for e in database if e["type"] == "sub_technique"),
        "tactics": {}
    }
    
    for entry in database:
        tactic = entry["tactic"]
        if tactic not in stats["tactics"]:
            stats["tactics"][tactic] = {"techniques": 0, "sub_techniques": 0}
        stats["tactics"][tactic][entry["type"] + "s"] = stats["tactics"][tactic].get(entry["type"] + "s", 0) + 1
    
    return stats


def main():
    """Main function to build database and run interactive query."""
    print("Building SPARTA database...")
    database = build_database()
    
    # Save to JSON file
    save_database(database, "sparta_database.json")
    
    # Print statistics
    stats = get_statistics(database)
    print(f"\nDatabase Statistics:")
    print(f"  Total entries: {stats['total_entries']}")
    print(f"  Techniques: {stats['techniques']}")
    print(f"  Sub-techniques: {stats['sub_techniques']}")
    print(f"\n  By Tactic:")
    for tactic, counts in stats['tactics'].items():
        print(f"    {tactic}: {counts['techniques']} techniques, {counts['sub_techniques']} sub-techniques")
    
    # Run interactive query
    interactive_query(database)


if __name__ == "__main__":
    main()
