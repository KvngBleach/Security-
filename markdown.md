# Security Concepts

## Administrative/Managerial Controls are the policies and procedures I'm always talking about. They aren't as "cool" as a new software control, but they exist to give structure and guidance to individuals like you, and other members of your organization, ensuring nobody gets fined or causes a breach.

* Security Policies: Security policies are written documents that outline your company’s approach to cybersecurity. They define roles and responsibilities, acceptable use, access control policy, and more.

* Incident Response Plan: An incident response plan explains the process and procedures your organization should follow to identify, manage, and respond to security threats.

## Physical Controls limit the access to systems in a physical way; fences, CCTV, dogs... and everybody's favorite: fire sprinklers.

* Access Control Systems: Keycards or biometric scanners help restrict entry to authorized personnel only.

* Surveillance Cameras: Surveillance cameras monitor activities and deter crime by making potential intruders aware they are being watched. Additionally, they provide useful evidence for investigations.

* Security Personnel: Employing trained security guards to patrol the premises can discourage unauthorized personnel from entering your premises.

* Fencing and Barriers: Fences and barriers dissuade potential intruders from entering your premises.

## Technical/Logical Controls are those that limit access on a hardware or software basis, such as encryption, fingerprint readers, authentication, or Trusted Platform Modules (TPMs). These don't limit access to the physical systems the way physical controls do, but rather access to the data or contents.

* Firewalls: Firewalls check and control incoming and outgoing network traffic based on predetermined security rules. They act as a security barrier between trusted internal networks and untrusted external networks, effectively blocking unauthorized access and helping to prevent cyber attacks.

* Multi-factor Authentication (MFA): If you implement Multi-Factor Authentication (MFA) in your organization, users must provide multiple forms of verification, such as a password and a text message code, before accessing systems. This practice makes it challenging for threat actors to gain unauthorized access to user accounts, even if they successfully obtain passwords using brute force attack tools.

* Encryption: Encrypting sensitive data in your organization protects it from prying eyes. Even if hackers intercept your data during transmission or gain unauthorized access, they cannot read or understand it.

* Intrusion Detection and Prevention System (IDPS): IDPS detect and block security threats before it can cause any harm to your IT network. It is an important technical security control used by most organizations today.

* Endpoint Protection Platform (EPP): Endpoint protection platforms offer various security features, such as data loss protection, protection from malicious downloads, incident investigation and remediation, and more. These features help protect endpoints from security threats.

## Operational Controls are those that involve people conducting processes on a day-to-day level. Examples could include awareness training, asset classification, and reviewing log files.

* Configuration Management: A configuration management plan ensures that all systems use secure baseline settings instead of default settings. This helps prevent hackers from exploiting vulnerabilities that result from poor configuration settings.

* Security Awareness Training: Regular cybersecurity training helps your employees follow cybersecurity best practices, such as creating strong passwords, understanding threats of social engineering attacks, and avoiding clicking unknown links. This helps your company to meet its overall security goals.

* User account Management: Managing user accounts involves giving the right access to individuals based on their roles and deleting accounts once employees leave the company. Use account management helps ensure that data access aligns with the least privilege principle.

* Patch Management: Regularly updating and applying software patches is an ongoing operational task to prevent vulnerabilities, ensuring that day-to-day system management is in line with security goals. You can explore these best patch management software to automate updates in your organization.

# Defending Against Attacks

## Preventative Controls

</table> Preventive security controls, as the name suggests, protect your IT infrastructure from threats and attacks by preventing security threats from occurring. Some people call them preventative controls, but both terms mean the same thing. 

Here are key examples of preventive controls.

* Hardening: Application hardening involves enhancing security beyond the default settings. This process includes actions like changing default passwords to strong ones, enabling multi-factor authentication, blocking open ports, and deactivating unnecessary accounts. Reducing the attack surface by hardening limits opportunities for hackers to exploit vulnerabilities in the application.

* Firewall: A firewall monitors and controls incoming and outgoing traffic based on predetermined security rules. By filtering malicious data packets, a firewall can block unauthorized access while allowing legitimate traffic. This prevents hackers from reaching internal systems, thereby acting as an effective preventive security control. You can explore these managed firewalls to find the best solution for your company.

* Intrusion Prevention System (IPS): An Intrusion Prevention System (IPS) actively detects and blocks security threats before they can reach your network, preventing potential security incidents. We have prepared a list of the best IPS software to help you make an informed decision based on your needs.

* Antivirus Software: An Antivirus program protects systems from various types of malware, including viruses, ransomware, spyware, and more. You can check these antivirus software to pick the right program for your business.

* Regular Software Updates: Keeping your systems’ software and operating systems up-to-date prevents threat actors from exploiting known vulnerabilities to enter your network.

* Account Disablement Policy: An account disablement policy makes sure that all accounts associated with an employee are disabled when they leave your organization. This prevents them from accessing confidential data after their departure. Failing to deactivate ex-employee accounts poses a severe security risk, as they could leak sensitive information to competitors or post it online out of resentment, causing a data breach.

## Detective Controls are only triggered during or after an event, such as video surveillance, or intrusion detection systems.

* Security Incident Event Management Tools (SIEM): SIEM systems collect and analyze data from multiple networking sources, such as router, firewall, and endpoints to detect security threats in real time. They help identify suspicious activities and provide alerts for possible incidents.

* Intrusion Detection System: An IDS monitors network traffic or system activities to detect any unusual or unauthorized actions. When it detects potential threats or intrusions, it generates alerts, allowing security teams to respond promptly.

* Motion Detectors: These devices detect movements in areas where there shouldn’t be any activity, such as restricted areas. Motion detectors alert security personnel to investigate any detected motion that could indicate an intrusion.

* Video Surveillance Camera: These cameras record activities in various areas of your facility, allowing your security teams to use this footage to detect suspicious behavior or review incidents after they occur to understand how they happened.

## Deterrents discourage threats from attempting to exploit a vulnerability, such as a "Guard Dog" sign, or dogs.

* Warning Signs: Warning signs stating that the facility is under surveillance cameras can discourage many intruders from entering.

* Login Banners: Displaying login banners that declare unauthorized access a crime can deter your staff members from attempting to access accounts they don’t own, even if they know the login credentials.

* Security Guards: The presence of security guards in your facility can discourage many unauthorized individuals from entering your premises.

* Lighting: Proper lighting that eliminates dark spots in your facility can deter intruders who use darkness to gain unauthorized entry into a building.

* Security Policies: Security policies that clearly outline the disciplinary consequences of violating cybersecurity best practices can discourage employees from showing a lax attitude towards cybersecurity.

## Corrective Controls are able to take an action from one state to another. This is where fail open and fail closed controls are addressed.

* Antivirus Software: After an infection occurs, antivirus programs can scan the device, quarantine infected files, and restore the system to a secure state.

* Restoration from Backups: If data is lost due to a cyberattack or system failure, restoring from backups helps recover the information and minimize downtime.

* Password Resets: After a security breach occurs, you should reset all passwords to prevent unauthorized access. This process helps secure accounts and ensures that only authorized users regain access.

* Security Training: Providing additional employee training after a security incident helps raise awareness of potential threats and proper security practices. This training reinforces the importance of following security protocols and helps prevent future incidents.

## Compensating Controls are those that attempt to make up for the shortcomings of other controls, such as reviewing access logs regularly. This example is also a detective control, but compensating controls can be of various different types.

* Strict Access Controls: If an organization cannot segregate duties for sensitive processes, it might implement strict access controls and carry out regular security audits to monitor user activities.

* Data Loss Prevention (DLP) Solutions: If encryption is not possible for data in transit, organizations may implement DLP solutions to monitor and control the flow of sensitive information outside the network.

* Employee Training and Awareness: If technical controls like spam filters cannot effectively prevent phishing attacks, providing extensive staff training on recognizing and responding to phishing attacks, email spoofing, typosquatting, and other security threats can serve as a compensating control.

## Directive Controls

* Acceptable Use Policy: A written document outlining the acceptable behaviors and practices for using organizational resources, such as computers, networks, and internet access.

* Security Awareness Training: These training programs are designed to educate employees about cybersecurity threats, best practices, and their roles in protecting the organization’s assets and information.

* Incident Response Plan: An incident response plan is a written document that guides security teams in taking the necessary steps to minimize the impact of a security incident on the confidentiality, integrity, and availability of resources. It also helps restore systems to normal operation.

## Importance of Security Controls

* Risk Mitigation: Security controls reduce the likelihood and impact of security incidents.

* Data Protection: Security controls protect your data from unauthorized access. They can help you ensure the confidentiality, integrity, and availability of your data resources. You can check these data security solutions to protect data in your organization.

* Regulatory Compliance: Depending on your industry, you may be liable to some regulations like the General Data Protection Regulation (GDPR) or the Health Insurance Portability and Accountability Act (HIPPA) that require you to implement security measures to protect your customers’ data. Implementation of various security controls strategically can help you meet regulatory compliance.

* Trust and Reputation: Security controls reduce the frequency and impact of security incidents. This prioritization of security enhances trust and reputation among customers, vendors, stakeholders, and third parties, as they feel more secure working with organizations that take security seriously.