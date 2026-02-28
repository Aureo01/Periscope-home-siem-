# Periscope v1.0

I built this for practice,learning-focused,lightweight and experimental

---

## About This Project

Periscope is a small defensive monitoring tool I built while studying how SIEM systems work internally.

The goal was not to create a production-ready platform, but to understand:

- How log parsing works
- How detection rules are structured
- How alerts are generated
- How severity levels are handled
- How a basic SOC-style dashboard can be visualized in real time

This project is purely educational.

---

## What It Does

Periscope monitors log files (or simulated events) and:

- Parses log lines
- Detects predefined threat patterns
- Assigns severity levels
- Tracks source IP activity
- Generates alerts based on thresholds
- Displays everything in a live terminal dashboard

---

## Detection Rules (Educational Examples)

Includes simple pattern-based detection for:

- SSH brute force attempts
- SQL injection patterns
- XSS attempts
- Path traversal
- Privilege escalation indicators
- Reverse shell / command execution patterns
- Possible data exfiltration behavior

These rules are simplified and intended for learning purposes only.

---

###  Simulation Mode
Allows testing without real logs:

```bash
python3 periscope.py --simulate

python3 periscope.py /var/log/auth.log

Simulation mode:

python3 periscope.py --simulate --duration 60

Generate report on exit:

python3 periscope.py /var/log/auth.log --report 
