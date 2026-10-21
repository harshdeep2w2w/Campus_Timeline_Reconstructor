# 🎓 Simple Presentation Guide & Viva Defense Script
## Campus Network Attack – Timeline Reconstructor
**Easy-to-Understand Presentation Guide for College Evaluation**

---

### 📂 Presentation File Details
- **File Name:** [`Campus_Network_Attack_Timeline_Reconstructor_Presentation.pptx`](file:///c:/Users/DELL/OneDrive/Desktop/Campus_Timeline_Reconstructor/Campus_Network_Attack_Timeline_Reconstructor_Presentation.pptx)
- **Slide Count:** **17 Slides** (Widescreen 16:9 format)
- **Language Style:** **Simple, Plain English** (No confusing academic jargon!)
- **Embedded Speaker Notes:** Every slide has a **"What to Say to Your Teacher"** script inside PowerPoint's Notes pane.

---

## 📑 Slide-by-Slide Walkthrough (Easy English)

---

### **Slide 1: Title Slide**
- **Title:** Campus Network Attack – Timeline Reconstructor
- **Subtitle:** A Smart Security Tool that Rebuilds Cyber Attack Timelines from Campus Network Logs
- **Key Badges:**
  - *What it does:* Finds hackers & rebuilds the attack story
  - *Easy to use:* Visual dashboard with interactive network map
  - *Verified & Ready:* Passed all 68 automated software tests
- **🎙️ What to Say to Your Teacher:**
  > *"Good morning teacher. Today I am presenting my project called 'Campus Network Attack - Timeline Reconstructor'. In simple words, this project acts like a digital detective for college campus networks. When an attack happens, it reads network logs, finds what the hacker did step-by-step, shows the story on an easy timeline, and draws a visual map of all connected computers."*

---

### **Slide 2: What is This Project? (The Big Picture)**
- **Left Card (The Simple Idea Behind the Project):**
  - **Like CCTV for Networks:** Just like security cameras record people entering buildings, routers and firewalls record every website and connection.
  - **The Problem with Logs:** These logs are stored in thousands of confusing plain text lines. Reading them by hand takes days.
  - **What Our Software Does:** It cleans up all the messy logs, connects the clues, and rebuilds the exact story of how a hacker broke in.
  - **Who Benefits:** College IT teams, teachers, students, and network administrators who need fast answers.
- **Right Card (What Can the User Do With It?):**
  - **Upload Any Log File:** Supports CSV, JSON, and Zeek logs.
  - **See the Attack Timeline:** Shows events in exact order of time.
  - **Spot Dangerous Activity:** Automatically alerts you to port scans, virus downloads, and data theft.
  - **View an Interactive Map:** Displays a visual diagram of all computers (bad computers glow red).
  - **Download a PDF Report:** 1-click report ready to print or email.
- **🎙️ What to Say to Your Teacher:**
  > *"Think of this project as a CCTV camera playback system, but for computer networks. Usually, network logs are just massive text files with millions of confusing numbers. Our project takes those text files and turns them into a clean story with charts, an interactive timeline, and a visual map. It lets an administrator see who got hacked, when it started, and what data was stolen in just a few clicks."*

---

### **Slide 3: Why is Campus Network Security So Difficult?**
- **Card 1 (Thousands of Unknown Devices):** Students and teachers bring personal phones and laptops onto campus Wi-Fi. The college IT team cannot control what software students install, so one infected laptop can silently attack college servers.
- **Card 2 (IP Addresses Keep Changing):** When a student walks between buildings, their laptop gets a new IP address via DHCP. An IP address that did an attack at 9:00 AM might belong to a totally innocent student by 10:00 AM!
- **Card 3 (Millions of Log Lines):** A normal campus generates over 100,000 log lines every single hour. No human can read them fast enough during a live attack.
- **🎙️ What to Say to Your Teacher:**
  > *"Here are the 3 real-world problems we solve: First, college Wi-Fi is crowded with thousands of personal student devices that might have malware. Second, IP addresses change constantly throughout the day via DHCP, so it's hard to tell who had which IP at each minute. Third, there are simply too many log lines for a human to read. Our project automates this entire process."*

---

### **Slide 4: Project Goals: What We Built**
- **Left Card (Key Goals We Set Out to Achieve):**
  - **Goal 1:** Read logs from different firewalls and Wi-Fi routers without crashing.
  - **Goal 2:** Convert all dates and time formats onto one unified clock.
  - **Goal 3:** Automatically catch hacking behavior (port scans, backdoor ports, brute force).
  - **Goal 4:** Connect the dots between related events.
- **Right Card (User Experience & Presentation Goals):**
  - **Goal 5:** Build a clean Dark Mode dashboard like a real Security Operations Center (SOC).
  - **Goal 6:** Create an interactive network map (nodes = computers, lines = connections).
  - **Goal 7:** Let the officer bookmark evidence and write investigation notes.
  - **Goal 8:** Generate a formal PDF incident report with one click.
- **🎙️ What to Say to Your Teacher:**
  > *"Teacher, our goals were simple: 1. Ingest files easily. 2. Fix all timestamps so they line up on a single timeline. 3. Automatically detect suspicious attacks. 4. Present everything in a clear visual dashboard with an interactive map, and allow 1-click PDF export. Every single one of these goals has been fully built and tested."*

---

### **Slide 5: How the System Works: 4 Simple Steps**
1. **Step 1: Upload (Ingest Log Files):** Upload CSV, JSON, or Zeek log files. The system checks format automatically.
2. **Step 2: Clean (Normalize Data):** Converts all dates into one matching time zone and verifies IP numbers.
3. **Step 3: Detect (Run Security Rules):** Checks for port scans, backdoors, and data uploads, and links clues together.
4. **Step 4: Show (Visuals & Reports):** Displays charts, draws a live network map, and creates a PDF report.
- **🎙️ What to Say to Your Teacher:**
  > *"Here is the simple step-by-step workflow: Step 1: The user uploads raw log files. Step 2: The cleaning engine standardizes timestamps and IP addresses into one format. Step 3: Our detection rules inspect the events to find suspicious hacking patterns. Step 4: The results are displayed on the web dashboard with charts, an interactive graph, and a PDF report generator."*

---

### **Slide 6: Technologies Used & Why We Chose Them**
- **Python 3 & Flask (Backend):** The #1 language for cybersecurity. Fast and lightweight web framework.
- **SQLite (Database):** Requires zero installation. Extremely fast query indexes (under 0.1s searches). 100% private.
- **Bootstrap 5 & Chart.js (Frontend):** Sleek Dark Mode interface with interactive bar and donut charts.
- **Cytoscape.js & ReportLab:** Cytoscape draws the live network map; ReportLab compiles clean PDF reports from Python.
- **🎙️ What to Say to Your Teacher:**
  > *"We chose Python and Flask because they are lightweight, reliable, and standard in cybersecurity. We chose SQLite because it needs zero configuration and keeps all sensitive college logs completely private on the local machine. For visualization, we used Chart.js for graphs and Cytoscape.js to build the interactive network map. Finally, ReportLab creates professional PDF reports directly."*

---

### **Slide 7: Step 1 - Reading & Cleaning Messy Logs**
- **Handling Different Log Formats:** Reads CSV, TSV, JSON, and Zeek logs. Understands that `Source_IP`, `src_addr`, and `id.orig_h` all mean the same thing! Keeps the original raw text for proof.
- **Fixing Dates & IP Addresses:** Converts all date styles (Unix seconds, AM/PM) into one unified clock. Validates IP addresses and automatically tags events as Web, DNS, or Email.
- **🎙️ What to Say to Your Teacher:**
  > *"In real life, a Zeek log calls the IP 'id.orig_h', while a firewall calls it 'src_ip'. Our code automatically recognizes that these mean the same thing. More importantly, it puts all timestamps on the same clock so events can be sorted in exact order. Without this step, it is impossible to know what happened first during an attack."*

---

### **Slide 8: Step 2 - Connecting the Dots (Correlation Engine)**
- **1. Shared Computer Tracking:** Finds all computers that contacted the same server or were contacted by a hacker.
- **2. Following DNS Clues:** Links a computer looking up a bad domain (e.g. `malware-c2.xyz`) directly to its next connection attempt to that server.
- **3. Time Window Clustering:** Groups events happening within 5 minutes to spot fast attack bursts.
- **4. Related Event Finder:** Clicking any event immediately shows all other events connected to it.
- **🎙️ What to Say to Your Teacher:**
  > *"A single log line in isolation looks harmless. For example, visiting a website is normal. But if a computer looks up a suspicious website name, and two seconds later opens a hidden connection to that server, that is an attack! Our correlation engine links these clues together so the analyst sees the complete picture."*

---

### **Slide 9: Step 3 - The 6 Common Cyber Attacks We Catch**
| Attack Type | What Does the Attacker Do? (In Plain English) | Severity |
| :--- | :--- | :--- |
| **1. Port Scanning** | Checking many doors (ports) on a server to find an open door to break in. | **HIGH** |
| **2. Network Sweep** | Scanning across multiple computers on campus to see which ones are online. | **HIGH** |
| **3. Suspicious DNS Lookups** | Querying dangerous website names (like `.xyz`, `.tk`, `.top`) used by malware. | **HIGH** |
| **4. Unusual / Backdoor Port** | Connecting to known hacker ports (like `4444` used by Metasploit) to control a PC. | **CRITICAL** |
| **5. Rapid Traffic Burst** | Uploading huge amounts of data in a short time (data theft / exfiltration). | **HIGH** |
| **6. Password Brute Force** | Trying to guess passwords repeatedly (like 15 failed SSH logins in a row). | **MEDIUM** |
- **🎙️ What to Say to Your Teacher:**
  > *"Teacher, these are the 6 attacks our system catches automatically. 1. Port Scanning: checking doors on a server. 2. Network Sweep: finding other computers on the Wi-Fi. 3. Suspicious DNS: looking up dangerous websites. 4. Unusual Ports: hacker backdoors like port 4444. 5. Traffic Burst: stealing data rapidly. 6. Brute Force: guessing passwords over and over. Every rule is clear, explainable, and stores exact proof of what happened."*

---

### **Slide 10: The Demo Attack Story (What We Simulated)**
- **Phase 1: Student Connects (08:00 AM):** Laptop `10.0.1.45` joins campus Wi-Fi, visits normal student portals (`moodle`).
- **Phase 2: Scanning Server (09:00 AM):** Suddenly scans the Campus Web Server (`10.0.2.10`) on 10 ports.
- **Phase 3: Backdoor Shell (09:01 AM):** Queries `malware-c2.xyz` and connects to hacker port `4444` (Critical alert!).
- **Phase 4: Stealing Data & Moving (09:02 AM):** Rapidly uploads 20 chunks of stolen files. Another laptop (`10.0.1.78`) tries 15 failed SSH password attempts against admin servers.
- **🎙️ What to Say to Your Teacher:**
  > *"To test our system, we generated a realistic campus attack story with ~400 events. At 8:00 AM, a student laptop connects to Wi-Fi normally. At 9:00 AM, it suddenly scans the campus web server. At 9:01 AM, it opens a backdoor connection to a hacker server on port 4444. At 9:02 AM, it rapidly uploads stolen files. Then another laptop tries guessing admin passwords. Our system detects and reconstructs every single phase of this attack."*

---

### **Slide 11: The Main Dashboard: At-a-Glance Control**
- **4 Top KPI Cards:** Total Events (~400), Active Computers (35+), Security Alerts (10+), Severity Split.
- **Activity Timeline Chart:** Bar chart showing traffic hour-by-hour. The spike at 9:00 AM is clearly visible!
- **Top Talkers & Alert Feed:** Highlights which computer sent the most traffic (the hacker's laptop) and lists real-time warnings.
- **🎙️ What to Say to Your Teacher:**
  > *"This is the Main Dashboard. At the top, 4 stat cards summarize the network: 400 events, 35 hosts, and 10 alerts. The bar chart shows a clear spike at 9:00 AM, making it obvious when the attack occurred. The Top Talkers list immediately exposes the suspicious laptop."*

---

### **Slide 12: The Attack Timeline: Step-by-Step History**
- **Strict Chronological Order:** Events arranged earliest to latest, like chapters in a book.
- **Easy Filtering:** Filter by IP (e.g. `10.0.1.45`), protocol, or severity level with instant updates.
- **Full Detail Pop-Up:** Shows exact seconds, ports, original raw log line, and a button to pin it to an investigation.
- **🎙️ What to Say to Your Teacher:**
  > *"Time is the most important element in an investigation. Our timeline arranges every event in order. If an analyst enters '10.0.1.45', the screen filters down to show only that device's actions. Clicking any event opens a window showing the exact time, ports, and raw proof. This turns hours of manual log reading into seconds of point-and-click investigation."*

---

### **Slide 13: Interactive Network Map (Cytoscape.js)**
- **Visual Nodes & Lines:** Computers are bubbles; connections are lines. Normal = Blue, Servers = Yellow, Infected = Red!
- **Interactive:** Drag nodes around, zoom in/out, and switch between physics and circle layouts.
- **Click to Inspect:** Clicking any bubble opens a side panel showing who it talked to and its alerts.
- **🎙️ What to Say to Your Teacher:**
  > *"While the timeline tells you 'when' an attack happened, this map shows you 'who talked to whom'. Normal computers appear in blue, servers in yellow, and bad computers glow red. You can drag nodes around and click any computer to see its connections. This makes it extremely easy to explain an attack to a teacher, dean, or police officer."*

---

### **Slide 14: Investigation Workspace: Managing Cases**
- **Create Cases:** Open named incident cases (e.g. 'Library Wi-Fi Incident') with time windows.
- **Bookmark Evidence:** Pin suspicious events and suspect computer IPs into the case folder.
- **Analyst Notes:** Document what happened and what steps were taken.
- **Status Workflow:** Change alert statuses: `Open` $\rightarrow$ `Acknowledged` $\rightarrow$ `Resolved` $\rightarrow$ `False Positive`.
- **🎙️ What to Say to Your Teacher:**
  > *"Finding an attack is only half the job; documenting it is the other half. In our Investigation Workspace, an analyst can open a formal case, bookmark suspicious events, tag suspect computers, and write down notes. Alerts can be marked as Resolved or False Positive. This gives a structured workflow just like professional cybersecurity tools."*

---

### **Slide 15: 1-Click PDF Incident Report Generator**
- **Executive Summary:** Summarizes what happened, how many computers were affected, and risk level.
- **Neat Timeline Table:** Formatted table of events in order of time with IPs, ports, and protocols.
- **Triggered Alerts:** Details the exact rules broken and technical evidence.
- **Export Formats:** Generates clean PDF in under 2 seconds. Also supports CSV and JSON data exports.
- **🎙️ What to Say to Your Teacher:**
  > *"When an investigation is finished, management needs a written report. With one click on the 'Export PDF' button, our Python ReportLab engine compiles an executive-ready PDF report. It includes a summary, chronological table, alert evidence, and analyst notes. Users can also export the data as CSV or JSON."*

---

### **Slide 16: Testing & Proof: 100% Passed (68 Tests)**
- **Pytest Results:** **68 / 68 Tests Passed** in **12.77 seconds** with **ZERO errors**.
- **Coverage:**
  - *Parsers (22 tests):* Tested with broken headers, missing fields, and bad timestamps.
  - *Timeline (14 tests):* Tested chronological sorting and DNS linking.
  - *Threat Detectors (9 tests):* Confirmed all 6 rules work and do not produce false alarms.
  - *APIs & Reports (23 tests):* Verified all web endpoints and PDF exports compile cleanly.
- **🎙️ What to Say to Your Teacher:**
  > *"Teacher, we did not just write the application; we thoroughly tested it. We wrote an automated test suite of 68 individual test cases using pytest. All 68 tests passed with 100% success in under 13 seconds. This proves that our parsers don't crash on bad files, our detection rules don't produce false alarms, and our PDF reports generate smoothly every single time."*

---

### **Slide 17: Project Summary, Future Plans & Q&A**
- **Future Improvements:** Add Machine Learning (AI) for unknown zero-day attacks, live packet capture, and automatic IP threat reputation checks.
- **Key Takeaways:** Fully working, saves days of manual effort, and runs 100% offline with complete privacy.
- **🎙️ What to Say to Your Teacher:**
  > *"In conclusion, our project solves a major real-world headache for college IT teams. It turns chaotic network logs into a simple timeline and visual map, making it fast and easy to catch attackers. In the future, we hope to add machine learning for zero-day threats and live packet capture. Thank you very much, teacher. I am now ready for your questions and to show the live demo."*
