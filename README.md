# phishing-detection-project
# Phishing Detection System

An AI-powered web application and browser extension designed to analyze text and URLs to determine whether they are legitimate or potential phishing attempts.

## Overview

The Phishing Detection System is a comprehensive solution that leverages Machine Learning to classify user inputs. It includes a backend REST API built with FastAPI, a web-based dashboard with user authentication and history tracking, and a Google Chrome browser extension for real-time text and URL scanning.

## Key Features

- **Machine Learning Detection**: Uses a trained Scikit-Learn model (`model.pkl`) and TF-IDF vectorizer (`vectorizer.pkl`) to analyze text patterns and predict phishing threats.
- **Secure Authentication**: Includes a complete signup and login flow with hashed passwords and JWT-based session management.
- **User Dashboard**: A personalized dashboard that keeps a history of your past scans and provides basic analytics using Matplotlib charts.
- **URL Extraction**: Automatically extracts and analyzes URLs from any text block submitted for scanning.
- **RESTful API**: Exposes a `/api/v1/scan` endpoint for cross-platform integration.
- **Browser Extension**: A companion Chrome extension ("Phishing Shield") that connects to the API to scan the current page or highlighted text.

## Project Structure

```text
phishing-detection-project/
├── data/                  # Datasets used for training the model
├── extension/             # Chrome browser extension source code
│   ├── manifest.json      # Extension configuration
│   ├── popup.html         # Extension UI
│   └── popup.js           # Extension logic
├── notebooks/             # Jupyter notebooks for data exploration and model training
├── src/                   # Backend Python source code
│   ├── app.py             # Main FastAPI application
│   ├── db.py              # Database interaction logic
│   ├── day1_load_data.py  # Data loading scripts
│   └── train_model.py     # Script to train the ML model
├── static/                # Static assets (CSS)
│   └── style.css          # Global stylesheet
├── templates/             # Jinja2 HTML templates for the web app
│   ├── dashboard.html     # User dashboard template
│   ├── login.html         # Login page template
│   ├── signup.html        # Signup page template
│   └── history.html       # Prediction history template
├── model.pkl              # Pickled trained ML model
├── vectorizer.pkl         # Pickled TF-IDF vectorizer
├── phishing_app.db        # SQLite database for application data (predictions)
├── users.db               # SQLite database for user accounts
└── requirements.txt       # Python project dependencies
```

## Technology Stack

- **Backend**: Python 3.x, FastAPI, Jinja2, SQLite
- **Frontend**: HTML5, Vanilla CSS, JavaScript
- **Machine Learning**: Scikit-Learn, Pandas, NumPy, NLTK
- **Security**: PyJWT, Hashlib (PBKDF2 HMAC)
- **Data Visualization**: Matplotlib

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-detection-project.git
cd phishing-detection-project
```

### 2. Set Up a Virtual Environment

It is recommended to use a virtual environment to manage dependencies:

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

*(Note: You may also need to install FastAPI and Uvicorn if they are not included in the `requirements.txt`: `pip install fastapi uvicorn jinja2 python-multipart`)*

### 4. Run the Application

Start the FastAPI development server:

```bash
uvicorn src.app:app --reload
```

The web application will be accessible at `http://127.0.0.1:8000`.

## Browser Extension Setup

To install the "Phishing Shield" Chrome extension:

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle switch in the top right corner.
3. Click the **Load unpacked** button.
4. Select the `extension` folder located inside the `phishing-detection-project` directory.
5. The "Phishing Shield" extension should now appear in your browser toolbar. Pin it for easy access!

*(Make sure your local FastAPI backend is running for the extension to work properly, as it communicates with `http://localhost:8000/api/v1/scan`)*

## Usage

1. **Web App**: Open `http://localhost:8000`, sign up for an account, and log in. You can paste any text or URL into the dashboard to scan it for phishing indicators.
2. **Dashboard**: View your past scans and the ratio of legitimate vs. phishing content in the provided charts.
3. **Extension**: Click the extension icon on any webpage to scan the current context.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
