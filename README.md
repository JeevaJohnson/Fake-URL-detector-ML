# Phishing URL Detection System

## Overview

This project detects whether a URL is:

* Legitimate
* Suspicious
* Phishing

## Features

* Machine Learning (XGBoost + CalibratedClassifierCV)
* Advanced feature engineering (entropy, keywords, domain analysis)
* Heuristic rules for improved detection
* REST API using Flask

## How to Run

1. Install dependencies:
   pip install -r requirements.txt

2. Run the app:
   python app.py

## API Endpoint

POST /predict

Example:
{
"url": "http://example.com"
}

## Output

* prediction
* confidence
* reasons
