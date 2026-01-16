# Email Forensics – Post-Phishing Analysis Tool (Projet 7)

This project implements an automated forensic analysis tool for simulated phishing emails.
It reproduces the workflow of a SOC analyst handling a reported malicious email in a controlled lab environment.

The tool parses a locally generated .eml file and extracts critical Indicators of Compromise (IOCs) such as phishing URLs, source IP addresses, suspicious sender domains, and malicious attachments.
A structured technical report is generated at the end of the analysis.

Project developed for UEM112 – Piratage éthique et défense des systèmes.


## Objective

The goal of this project is to analyze a simulated phishing email without opening it in a real email client and extract forensic evidence for investigation purposes.

The script automatically:

Parses email headers

Extracts source IP addresses

Detects phishing URLs

Flags suspicious sender domains (typosquatting)

Extracts attachments

Analyzes metadata using ExifTool

Generates a technical report


## Lab Environment

Operating system: Kali Linux or Parrot OS

Network: no outbound internet connection

Email source: locally generated .eml file

Attachments: locally generated files

Tools: Python, ExifTool, ReportLab


## Repository Structure

<img width="657" height="558" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64" src="https://github.com/user-attachments/assets/53526e62-6133-4421-a191-eb822e15e6e1" />

<img width="1366" height="672" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64_16_01_2026_16_31_33" src="https://github.com/user-attachments/assets/c3a4f21a-fff8-4801-b931-b2372a821e54" />


## Ethical Notice

This project analyzes only locally generated emails.
No real emails or personal data are used.
Compliant with Algerian cybersecurity law 19-05.

<img width="1366" height="672" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64_16_01_2026_16_34_07" src="https://github.com/user-attachments/assets/e5fafc5d-57a4-4b4b-aa4a-c2640c501405" />


<img width="1366" height="672" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64_16_01_2026_16_33_20" src="https://github.com/user-attachments/assets/0a229553-40b7-408e-98a5-554b31725198" />


<img width="1366" height="672" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64_16_01_2026_16_27_21" src="https://github.com/user-attachments/assets/62fb9ec8-d6b1-45ff-a0e4-739146c310be" />


<img width="1366" height="672" alt="VirtualBox_kali-linux-2025 4-virtualbox-amd64_16_01_2026_16_02_32" src="https://github.com/user-attachments/assets/74942a02-99ed-45b6-8e34-0b2042662573" />

