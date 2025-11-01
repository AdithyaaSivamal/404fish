

# 📊 Internet Background Noise Visualizer (Application)

> This repository contains the application code for the **Internet Background Noise Visualizer**, a multi-region, real-time threat intelligence dashboard.
>
> This application is a Python **FastAPI** backend with a vanilla **HTML/CSS/JavaScript** frontend.

-----

### 🖥️ Demo

**[A GIF OR SCREENSHOT OF YOUR DASHBOARD UI WOULD BE PERFECT HERE]**

-----

### Table of Contents

  * [Features](#-features)
  * [Deployment](#-deployment)
  * [Infrastructure](#-infrastructure)

-----

## 🚀 Features

### API Backend

  * **High-Performance:** Built with FastAPI and an `asyncpg` backend to serve data to the frontend.
  * **Containerized:** A multi-stage `Dockerfile` creates a small, secure production image.

### Data Processing

  * **Multi-Region Polling:** A background processor (`run_log_processor`) polls data from multiple AWS CloudWatch Log Groups in different regions simultaneously.
  * **Real-time Enrichment:** Ingested IPs are enriched with:
      * **Geolocation:** (GeoLite2 City)
      * **ISP/ASN:** (GeoLite2 ASN)
      * **Reverse DNS (rDNS):** (Python `socket` library)
  * **Automatic Flagging:** Events are automatically flagged as "suspicious" by checking their hostname and ISP against an external keyword list (`suspicious_keywords.txt`).

### Interactive UI

  * **Live Map:** A `Leaflet.js` map with marker clustering shows incoming events.
  * **Drill-Down Feed:** A log feed that populates when a map cluster is clicked.
  * **Filtered Views:** Separate feeds for "Live" vs. "Flagged" events.
  * **Context Menu:** Right-click to manually flag IPs or perform external lookups.

-----

## 🐳 Deployment

This application is designed to be deployed to **AWS ECS Fargate**.

It is configured entirely by **environment variables** (e.g., `DB_HOST`, `CW_LOG_GROUPS_JSON`) which are injected by the Terraform infrastructure stack.

-----

## 🏗️ Infrastructure

The full IaC (Terraform) and CI/CD pipeline for this project can be found in its companion repository:

**[https://github.com/AdithyaaSivamal/404fish-infra]**
