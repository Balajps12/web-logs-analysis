# Web Log Analysis Script

## Overview

This Python script analyzes web server log files, processes them to count requests per IP address, identify the most accessed endpoint, and detect suspicious activity based on failed login attempts. The results are displayed in the terminal and saved to a CSV file.

## Features

- **IP Request Counts**: Counts the number of requests made by each IP address.
- **Most Accessed Endpoint**: Identifies the most frequently accessed endpoint.
- **Suspicious Activity Detection**: Detects IP addresses with failed login attempts (401 status or invalid credentials) exceeding a set threshold.
- **CSV Output**: Saves the analysis results in a CSV file.

## Requirements

- Python 3.x
- `re` (regular expressions module) - included in Python standard library.
- `csv` - included in Python standard library.

## Setup

1. Clone this repository to your local machine.

   ```bash
   git clone https://github.com/yourusername/web-log-analysis.git
