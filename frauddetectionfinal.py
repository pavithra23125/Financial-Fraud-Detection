import streamlit as st
import pandas as pd
import sqlite3
import numpy as np
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import os
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import altair as alt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import seaborn as sns
import matplotlib.pyplot as plt

# Page config
st.set_page_config(
    layout="wide", 
    page_title="Advanced AI Fraud Detection System", 
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Database setup
DATABASE_PATH = "fraud_detection.db"

def init_database():
    """Initialize SQLite database with required tables and predefined data"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Transactions table with enhanced fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            sender TEXT NOT NULL,
            sender_acc TEXT NOT NULL,
            receiver_acc TEXT NOT NULL,
            receiver_email TEXT,
            country TEXT NOT NULL,
            amount REAL NOT NULL,
            velocity INTEGER DEFAULT 0,
            vpn INTEGER DEFAULT 0,
            fraud INTEGER DEFAULT 0,
            suspicious INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            error TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            device_fingerprint TEXT,
            transaction_type TEXT DEFAULT 'TRANSFER',
            merchant_category TEXT,
            location_lat REAL,
            location_lng REAL
        )
    ''')
    
    # Analytics table for KPIs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analytics_kpis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            total_transactions INTEGER DEFAULT 0,
            fraud_transactions INTEGER DEFAULT 0,
            suspicious_transactions INTEGER DEFAULT 0,
            fraud_rate REAL DEFAULT 0.0,
            false_positive_rate REAL DEFAULT 0.0,
            detection_accuracy REAL DEFAULT 0.0,
            avg_amount REAL DEFAULT 0.0,
            total_amount REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Fraud patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fraud_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,
            pattern_description TEXT,
            frequency INTEGER DEFAULT 1,
            last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT DEFAULT 'Medium'
        )
    ''')
    
    # Check if users table is empty and populate with sample data
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    if user_count == 0:
        # Insert predefined sample users
        sample_users = [
            ('admin', 'admin123', 'Admin', 'admin@frauddetection.com'),
            ('john_doe', 'password123', 'User', 'john.doe@email.com'),
            ('alice_smith', 'alice456', 'User', 'alice.smith@email.com'),
            ('bob_johnson', 'bob789', 'User', 'bob.johnson@email.com'),
            ('sarah_wilson', 'sarah321', 'User', 'sarah.wilson@email.com'),
            ('mike_brown', 'mike654', 'User', 'mike.brown@email.com'),
            ('emma_davis', 'emma987', 'User', 'emma.davis@email.com'),
            ('david_miller', 'david111', 'User', 'david.miller@email.com'),
            ('lisa_garcia', 'lisa222', 'User', 'lisa.garcia@email.com'),
            ('tom_anderson', 'tom333', 'User', 'tom.anderson@email.com'),
            ('jennifer_taylor', 'jen444', 'User', 'jennifer.taylor@email.com'),
            ('michael_clark', 'mike555', 'User', 'michael.clark@email.com'),
            ('jessica_lewis', 'jess666', 'User', 'jessica.lewis@email.com'),
            ('ryan_walker', 'ryan777', 'User', 'ryan.walker@email.com'),
            ('amanda_hall', 'amanda888', 'User', 'amanda.hall@email.com'),
            ('chris_young', 'chris999', 'User', 'chris.young@email.com'),
            ('supervisor', 'super123', 'Admin', 'supervisor@frauddetection.com'),
            ('manager', 'manager456', 'Admin', 'manager@frauddetection.com'),
            ('analyst', 'analyst789', 'User', 'analyst@frauddetection.com'),
            ('demo_user', 'demo123', 'User', 'demo@frauddetection.com')
        ]
        
        cursor.executemany(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            sample_users
        )
        print("✅ Sample users loaded successfully!")
    
    # Check if transactions table is empty and populate with sample data
    cursor.execute("SELECT COUNT(*) FROM transactions")
    transaction_count = cursor.fetchone()[0]
    
    if transaction_count == 0:
        # Insert sample transactions for demo purposes
        sample_transactions = [
            ('TXN100001', 'john_doe', '12345612345678901', '12345687654321098', 'receiver1@email.com', 'India', 1500.0, 1, 0, 0, 0, 0.15, 'Transaction successful', '2024-10-01 10:30:00', '192.168.1.100', 'FP1001', 'TRANSFER', 'Online'),
            ('TXN100002', 'alice_smith', '65432112345678901', '65432187654321098', 'receiver2@email.com', 'USA', 2500.0, 1, 0, 0, 0, 0.20, 'Transaction successful', '2024-10-01 11:15:00', '192.168.1.101', 'FP1002', 'PAYMENT', 'Retail'),
            ('TXN100003', 'bob_johnson', '87543212345678901', '87543287654321098', 'receiver3@email.com', 'UK', 3200.0, 1, 0, 0, 0, 0.25, 'Transaction successful', '2024-10-01 12:00:00', '192.168.1.102', 'FP1003', 'TRANSFER', 'ATM'),
            ('TXN100004', 'sarah_wilson', '99999912345678901', '12345687654321098', 'receiver4@email.com', 'India', 5000.0, 1, 0, 1, 0, 0.85, 'FRAUD DETECTED: Account does not match India BIN pattern', '2024-10-01 13:30:00', '192.168.1.103', 'FP1004', 'TRANSFER', 'Online'),
            ('TXN100005', 'mike_brown', '11122212345678901', '11122287654321098', 'receiver5@email.com', 'Nigeria', 65000.0, 1, 1, 0, 1, 0.75, 'SUSPICIOUS: Large amount from high-risk country', '2024-10-01 14:15:00', '192.168.1.104', 'FP1005', 'CASH_OUT', 'Online'),
            ('TXN100006', 'emma_davis', '32198712345678901', '32198787654321098', 'receiver6@email.com', 'Germany', 1800.0, 2, 0, 0, 0, 0.30, 'Transaction successful', '2024-10-01 15:00:00', '192.168.1.105', 'FP1006', 'PAYMENT', 'Gas'),
            ('TXN100007', 'david_miller', '54678912345678901', '54678987654321098', 'receiver7@email.com', 'Japan', 4200.0, 1, 0, 0, 0, 0.35, 'Transaction successful', '2024-10-01 16:20:00', '192.168.1.106', 'FP1007', 'TRANSFER', 'Restaurant'),
            ('TXN100008', 'lisa_garcia', '12345612345678901', '12345687654321098', 'receiver8@email.com', 'India', 800.0, 6, 0, 1, 0, 0.90, 'FRAUD DETECTED: Excessive velocity (6 txn/min)', '2024-10-01 17:10:00', '192.168.1.107', 'FP1008', 'TRANSFER', 'Online'),
            ('TXN100009', 'tom_anderson', '65432212345678901', '65432287654321098', 'receiver9@email.com', 'Canada', 22000.0, 1, 1, 0, 1, 0.65, 'SUSPICIOUS: VPN usage with high amount transaction', '2024-10-01 18:00:00', '192.168.1.108', 'FP1009', 'DEBIT', 'Retail'),
            ('TXN100010', 'jennifer_taylor', '23891412345678901', '23891487654321098', 'receiver10@email.com', 'Australia', 3500.0, 1, 0, 0, 0, 0.28, 'Transaction successful', '2024-10-01 19:30:00', '192.168.1.109', 'FP1010', 'TRANSFER', 'Online')
        ]
        
        cursor.executemany('''
            INSERT INTO transactions (
                transaction_id, sender, sender_acc, receiver_acc, receiver_email,
                country, amount, velocity, vpn, fraud, suspicious, risk_score, error,
                timestamp, ip_address, device_fingerprint, transaction_type, merchant_category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_transactions)
        print("✅ Sample transactions loaded successfully!")
    
    conn.commit()
    conn.close()

def add_user_db(username, password, role, email):
    """Add user to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            (username, password, role, email)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_db(username):
    """Get user from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_all_users_db():
    """Get all users from database for admin view"""
    conn = sqlite3.connect(DATABASE_PATH)
    df = pd.read_sql_query("SELECT username, email, role, created_at FROM users ORDER BY created_at DESC", conn)
    conn.close()
    return df

def add_transaction_db(transaction_data):
    """Add transaction to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO transactions (
            transaction_id, sender, sender_acc, receiver_acc, receiver_email,
            country, amount, velocity, vpn, fraud, suspicious, risk_score, error,
            ip_address, device_fingerprint, transaction_type, merchant_category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', transaction_data)
    
    conn.commit()
    conn.close()

def get_transactions_db(user_role=None, username=None):
    """Get transactions from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    
    if user_role == "Admin":
        query = "SELECT * FROM transactions ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn)
    else:
        query = "SELECT * FROM transactions WHERE sender = ? ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn, params=(username,))
    
    conn.close()
    return df

def calculate_risk_score(transaction_data):
    """Calculate risk score using multiple factors"""
    score = 0.0
    
    # Amount-based risk (higher amounts = higher risk)
    if transaction_data['amount'] > 50000:
        score += 0.3
    elif transaction_data['amount'] > 10000:
        score += 0.2
    elif transaction_data['amount'] > 5000:
        score += 0.1
    
    # Velocity-based risk
    if transaction_data['velocity'] > 5:
        score += 0.4
    elif transaction_data['velocity'] > 3:
        score += 0.2
    
    # VPN usage
    if transaction_data['vpn']:
        score += 0.2
    
    # Time-based risk (late night transactions)
    current_hour = datetime.now().hour
    if current_hour >= 22 or current_hour <= 5:
        score += 0.1
    
    return min(score, 1.0)  # Cap at 1.0

def update_daily_kpis():
    """Update daily KPIs in analytics table"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    today = datetime.now().date().strftime('%Y-%m-%d')
    
    # Get today's transaction stats
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN fraud = 1 THEN 1 ELSE 0 END) as fraud,
            SUM(CASE WHEN suspicious = 1 THEN 1 ELSE 0 END) as suspicious,
            AVG(amount) as avg_amount,
            SUM(amount) as total_amount
        FROM transactions 
        WHERE DATE(timestamp) = ?
    ''', (today,))
    
    stats = cursor.fetchone()
    
    if stats[0] > 0:  # If there are transactions today
        fraud_rate = (stats[1] / stats[0]) * 100 if stats[0] > 0 else 0
        
        # Insert or update KPIs
        cursor.execute('''
            INSERT OR REPLACE INTO analytics_kpis 
            (date, total_transactions, fraud_transactions, suspicious_transactions, 
             fraud_rate, avg_amount, total_amount)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (today, stats[0], stats[1], stats[2], fraud_rate, stats[3], stats[4]))
    
    conn.commit()
    conn.close()

def send_email_notification(receiver, subject, body):
    """Enhanced email function with HTML support and better formatting"""
    try:
        sender = 'https.kppa@gmail.com'  # Your Gmail address
        password = 'rlra xhid lffq facn'   # Your Gmail app password
        
        # Create message with HTML support
        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = f"Fraud Detection System <{sender}>"
        message['To'] = receiver
        
        # Create HTML version of the message
        html_body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
              <div style="text-align: center; background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h1 style="margin: 0; font-size: 24px;">🛡️ AI Fraud Detection System</h1>
                <p style="margin: 5px 0 0 0; font-size: 14px;">Secure Transaction Monitoring</p>
              </div>
              <div style="padding: 20px;">
                {body}
              </div>
              <div style="text-align: center; margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <p style="margin: 0; font-size: 12px; color: #6c757d;">
                  This is an automated message from AI Fraud Detection System<br>
                  Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
              </div>
            </div>
          </body>
        </html>
        """
        
        # Attach HTML message
        html_part = MIMEText(html_body, 'html')
        message.attach(html_part)
        
        # Send email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, message.as_string())
        
        return True
    except Exception as e:
        st.error(f"❌ Email sending failed: {e}")
        return False

def send_otp_email(user_email, username, otp):
    """Send OTP email to user"""
    subject = "🔐 Your Login OTP - Fraud Detection System"
    
    body = f"""
    <h2 style="color: #2563eb;">Login Verification Required</h2>
    <p>Hello <strong>{username}</strong>,</p>
    <p>Someone is attempting to login to your Fraud Detection System account. If this was you, please use the OTP below:</p>
    
    <div style="text-align: center; margin: 30px 0;">
      <div style="background: #eff6ff; border: 2px solid #3b82f6; padding: 20px; border-radius: 8px; display: inline-block;">
        <h1 style="margin: 0; color: #1e40af; font-size: 32px; letter-spacing: 8px; font-family: monospace;">
          {otp}
        </h1>
        <p style="margin: 10px 0 0 0; color: #6b7280; font-size: 14px;">Valid for 10 minutes</p>
      </div>
    </div>
    
    <p><strong>Security Notice:</strong></p>
    <ul style="color: #6b7280;">
      <li>This OTP is valid for 10 minutes only</li>
      <li>Never share this OTP with anyone</li>
      <li>If you didn't request this login, please ignore this email</li>
    </ul>
    
    <div style="margin-top: 20px; padding: 15px; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 4px;">
      <p style="margin: 0; color: #92400e;">
        <strong>⚠️ Security Tip:</strong> Our system will never ask for your OTP via phone or other emails.
      </p>
    </div>
    """
    
    return send_email_notification(user_email, subject, body)

def send_transaction_email(receiver_email, transaction_data, is_fraud=False, is_suspicious=False):
    """Send transaction notification email to receiver"""
    transaction_id = transaction_data['transaction_id']
    sender_name = transaction_data['sender']
    amount = transaction_data['amount']
    country = transaction_data['country']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if is_fraud:
        subject = "🚨 FRAUD ALERT - Transaction Blocked"
        
        body = f"""
        <h2 style="color: #dc2626;">🚨 Fraudulent Transaction Blocked</h2>
        <p>A fraudulent transaction attempt to your account has been <strong style="color: #dc2626;">BLOCKED</strong> by our AI security system.</p>
        
        <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #dc2626;">Transaction Details:</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px 0; font-weight: bold;">Transaction ID:</td><td>{transaction_id}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Amount:</td><td style="color: #dc2626; font-weight: bold;">₹{amount:,.2f}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">From:</td><td>{sender_name}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Country:</td><td>{country}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Time:</td><td>{timestamp}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Status:</td><td style="color: #dc2626; font-weight: bold;">BLOCKED - FRAUD DETECTED</td></tr>
          </table>
        </div>
        """
        
    elif is_suspicious:
        subject = "⚠️ SUSPICIOUS ACTIVITY - Transaction Under Review"
        
        body = f"""
        <h2 style="color: #d97706;">⚠️ Suspicious Transaction Detected</h2>
        <p>Our AI system has flagged a transaction to your account as <strong style="color: #d97706;">SUSPICIOUS</strong> and is under review.</p>
        
        <div style="background: #fffbeb; border: 1px solid #fed7aa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #d97706;">Transaction Details:</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px 0; font-weight: bold;">Transaction ID:</td><td>{transaction_id}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Amount:</td><td style="color: #d97706; font-weight: bold;">₹{amount:,.2f}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">From:</td><td>{sender_name}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Country:</td><td>{country}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Time:</td><td>{timestamp}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Status:</td><td style="color: #d97706; font-weight: bold;">UNDER REVIEW - SUSPICIOUS</td></tr>
          </table>
        </div>
        """
        
    else:
        subject = "✅ Transaction Successful - Money Received"
        
        body = f"""
        <h2 style="color: #059669;">✅ Transaction Completed Successfully</h2>
        <p>Great news! You have received a secure transaction processed through our AI Fraud Detection System.</p>
        
        <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #059669;">Transaction Details:</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px 0; font-weight: bold;">Transaction ID:</td><td>{transaction_id}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Amount Received:</td><td style="color: #059669; font-weight: bold; font-size: 18px;">₹{amount:,.2f}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">From:</td><td>{sender_name}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Country:</td><td>{country}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Time:</td><td>{timestamp}</td></tr>
            <tr><td style="padding: 8px 0; font-weight: bold;">Status:</td><td style="color: #059669; font-weight: bold;">COMPLETED SUCCESSFULLY</td></tr>
          </table>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <div style="background: #10b981; color: white; padding: 15px 30px; border-radius: 25px; display: inline-block;">
            <span style="font-size: 24px;">🎉</span>
            <strong style="margin-left: 10px; font-size: 18px;">Money Successfully Received!</strong>
          </div>
        </div>
        """
    
    return send_email_notification(receiver_email, subject, body)

# Enhanced styling
st.markdown("""
    <style>
        .main {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 0;
        }
        
        .stApp > header {
            background-color: transparent;
        }
        
        .stApp {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .main-header {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 2rem;
            border-radius: 15px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        }
        
        .metric-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            margin: 0.5rem 0;
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }
        
        .fraud-alert {
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            animation: pulse 2s infinite;
        }
        
        .success-alert {
            background: linear-gradient(135deg, #51cf66, #40c057);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
        }
        
        .suspicious-alert {
            background: linear-gradient(135deg, #ffd43b, #fab005);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .sidebar .sidebar-content {
            background: linear-gradient(180deg, #2c3e50 0%, #3498db 100%);
        }
        
        .stButton > button {
            width: 100%;
            border-radius: 25px;
            border: none;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            font-weight: bold;
            padding: 0.75rem;
            transition: all 0.3s ease;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .kpi-container {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .kpi-box {
            background: white;
            padding: 1.5rem;
            border-radius: 15px;
            text-align: center;
            min-width: 200px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .predefined-users {
            background: rgba(255, 255, 255, 0.1);
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .email-status {
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            text-align: center;
            font-weight: bold;
        }
        
        .email-success {
            background: #d1fae5;
            color: #065f46;
            border: 1px solid #10b981;
        }
        
        .email-error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #ef4444;
        }
    </style>
""", unsafe_allow_html=True)

# Initialize database with sample data
init_database()

# Enhanced header
st.markdown('''
    <div class="main-header">
        <h1 style="color: white; margin: 0; font-size: 2.5rem;">
            🛡️ Advanced AI Fraud Detection System
        </h1>
        <p style="color: #e8f4fd; margin: 0.5rem 0 0 0; font-size: 1.2rem;">
            Real-time Transaction Monitoring & Email Notifications
        </p>
    </div>
''', unsafe_allow_html=True)

# Session state initialization
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "user_email" not in st.session_state:
    st.session_state.user_email = None
if "otp" not in st.session_state:
    st.session_state.otp = None
if "otp_stage" not in st.session_state:
    st.session_state.otp_stage = False
if "last_txn_time" not in st.session_state:
    st.session_state.last_txn_time = {}

# Enhanced country data with more details
allowed_countries = {
    'India': {'code': 91, 'bin': 123456, 'risk_level': 'Medium', 'timezone': 'UTC+5:30'},
    'USA': {'code': 1, 'bin': 654321, 'risk_level': 'Low', 'timezone': 'UTC-5'},
    'UK': {'code': 44, 'bin': 875432, 'risk_level': 'Low', 'timezone': 'UTC+0'},
    'Germany': {'code': 49, 'bin': 321987, 'risk_level': 'Low', 'timezone': 'UTC+1'},
    'Japan': {'code': 81, 'bin': 546789, 'risk_level': 'Low', 'timezone': 'UTC+9'},
    'Australia': {'code': 61, 'bin': 238914, 'risk_level': 'Low', 'timezone': 'UTC+10'},
    'France': {'code': 33, 'bin': 678234, 'risk_level': 'Low', 'timezone': 'UTC+1'},
    'Singapore': {'code': 65, 'bin': 278912, 'risk_level': 'Low', 'timezone': 'UTC+8'},
    'Canada': {'code': 1, 'bin': 654322, 'risk_level': 'Low', 'timezone': 'UTC-5'},
    'Brazil': {'code': 55, 'bin': 987654, 'risk_level': 'High', 'timezone': 'UTC-3'},
    'Nigeria': {'code': 234, 'bin': 111222, 'risk_level': 'High', 'timezone': 'UTC+1'},
    'Russia': {'code': 7, 'bin': 333444, 'risk_level': 'High', 'timezone': 'UTC+3'}
}

# Enhanced sidebar navigation
menu = st.sidebar.selectbox(
    "🧭 Navigation",
    ["🏠 Login", "📝 Register", "💸 Transaction", "📜 History", "📊 Dashboard", "🔍 Analytics", "👥 User Management", "⚙️ Admin Panel"],
    index=0
)

# Registration Page
if menu == "📝 Register":
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.subheader("🔐 Create New Account")
    
    # Show predefined users info
    st.markdown('''
        <div class="predefined-users">
            <h4 style="color: white; margin-bottom: 10px;">💡 Quick Demo Access</h4>
            <p style="color: #e8f4fd; margin: 5px 0;">Use these predefined accounts for instant access:</p>
            <p style="color: #ffd700; margin: 5px 0;"><strong>Admin:</strong> admin / admin123</p>
            <p style="color: #ffd700; margin: 5px 0;"><strong>User:</strong> demo_user / demo123</p>
            <p style="color: #e8f4fd; margin: 5px 0;">Or create your own account below ⬇️</p>
        </div>
    ''', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        new_username = st.text_input("👤 Username", key="reg_un")
        new_password = st.text_input("🔒 Password", type="password", key="reg_pw")
    with col2:
        new_email = st.text_input("📧 Email (for OTP)", key="reg_em", help="Enter a valid email address to receive OTP codes")
        new_role = st.selectbox("👥 Role", ["User", "Admin"], key="reg_role")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("✅ Create Account", key="regbut"):
            if not all([new_username, new_password, new_email]):
                st.error("❌ Please fill all fields.")
            else:
                if add_user_db(new_username, new_password, new_role, new_email):
                    st.success("✅ Registration successful! Please login.")
                    st.info("📧 Use your registered email to receive OTP codes during login.")
                else:
                    st.error("❌ Username already exists!")
    
    st.markdown('</div>', unsafe_allow_html=True)

# Login Page
elif menu == "🏠 Login":
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.subheader("🔑 Secure Login (Real OTP via Email)")
    
    # Show sample accounts for quick access
    st.markdown('''
        <div class="predefined-users">
            <h4 style="color: white;">🚀 Quick Access Accounts</h4>
            <p style="color: #e8f4fd; margin: 5px 0;"><strong>Note:</strong> Replace sample emails with your real email to receive OTP</p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
                <div>
                    <p style="color: #ffd700; margin: 2px 0;"><strong>👑 Admin Accounts:</strong></p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">admin / admin123</p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">supervisor / super123</p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">manager / manager456</p>
                </div>
                <div>
                    <p style="color: #ffd700; margin: 2px 0;"><strong>👤 User Accounts:</strong></p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">demo_user / demo123</p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">john_doe / password123</p>
                    <p style="color: #e8f4fd; margin: 2px 0; font-size: 14px;">alice_smith / alice456</p>
                </div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        role = st.selectbox("👥 Login as", ["User", "Admin"], key="log_role")
        uname = st.text_input("👤 Username", key="log_un")
    with col2:
        pwd = st.text_input("🔒 Password", type='password', key="log_pw")
        st.write("") # Space for alignment
    
    c1, c2, c3 = st.columns([1, 1, 1])
    with c2:
        if st.button("📧 Send OTP to Email", key="otpget"):
            user = get_user_db(uname)
            if user and user[2] == pwd and user[3].lower() == role.lower():
                otp = random.randint(100000, 999999)
                st.session_state.otp = otp
                st.session_state.user_email = user[4]
                st.session_state.current_user = uname
                st.session_state.user_role = role
                st.session_state.otp_stage = True
                
                # Send real OTP email
                with st.spinner("Sending OTP to your email..."):
                    email_sent = send_otp_email(user[4], uname, otp)
                    
                if email_sent:
                    st.markdown('<div class="email-status email-success">✅ OTP sent successfully to your email!</div>', unsafe_allow_html=True)
                    st.info(f"📧 Check your email: **{user[4]}** for the 6-digit OTP code")
                else:
                    st.markdown('<div class="email-status email-error">❌ Failed to send OTP email</div>', unsafe_allow_html=True)
                    st.info(f"🔐 Demo OTP (email failed): **{otp}**")
                    
            else:
                st.error("❌ Invalid credentials!")
    
    if st.session_state.otp_stage:
        st.markdown("---")
        st.info("📬 Check your email inbox (and spam folder) for the OTP code")
        otp_input = st.text_input("🔐 Enter 6-digit OTP from email", key="otpval", max_chars=6)
        c1, c2, c3 = st.columns([1, 1, 1])
        with c2:
            if st.button("🚀 Verify & Login", key="logbut"):
                if str(otp_input) == str(st.session_state.otp):
                    st.session_state.logged_in = True
                    st.success("✅ Login successful!")
                    st.session_state.otp = None
                    st.session_state.otp_stage = False
                    st.rerun()
                else:
                    st.error("❌ Invalid OTP! Please check your email and try again.")
    
    st.markdown('</div>', unsafe_allow_html=True)
elif not st.session_state.logged_in:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.warning("⚠️ Please login to access the system.")
    st.markdown('</div>', unsafe_allow_html=True)

# Transaction Page
elif menu == "💸 Transaction":
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.header("💳 Process Transaction")
    
    # User info display
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"👤 **User:** {st.session_state.current_user} ({st.session_state.user_role})")
    with col2:
        st.info(f"📧 **Alert Email:** {st.session_state.user_email}")
    
    # Transaction form
    col1, col2, col3 = st.columns(3)
    
    with col1:
        country = st.selectbox("🌍 Country", list(allowed_countries.keys()))
        from_acc = st.text_input("📤 From Account", help="Enter sender's account number")
        amount = st.number_input("💰 Amount (₹)", min_value=10.0, max_value=100000.0, value=500.0)
        
    with col2:
        to_acc = st.text_input("📥 To Account", help="Enter receiver's account number")
        receiver_email = st.text_input("📧 Receiver Email", help="Email to notify receiver about transaction")
        transaction_type = st.selectbox("🔄 Transaction Type", ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"])
        
    with col3:
        vpn = st.selectbox("🔒 VPN Usage", [0, 1], help="Select 1 if using VPN")
        merchant_category = st.selectbox("🏪 Merchant Category", ["Online", "Retail", "ATM", "Gas", "Restaurant"])
        st.info(f"🏦 **BIN for {country}:** {allowed_countries[country]['bin']}")
    
    # Risk indicators
    risk_level = allowed_countries[country]['risk_level']
    if risk_level == 'High':
        st.warning(f"⚠️ **High Risk Country:** {country}")
    elif risk_level == 'Medium':
        st.info(f"ℹ️ **Medium Risk Country:** {country}")
    else:
        st.success(f"✅ **Low Risk Country:** {country}")
    
    # Submit transaction
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("🚀 Submit Transaction", key="txsub"):
            if not receiver_email:
                st.error("❌ Please enter receiver's email address!")
                st.markdown('</div>', unsafe_allow_html=True)
                st.stop()
                
            now = datetime.now()
            user_key = f"{st.session_state.current_user}_{from_acc}"
            
            # Calculate velocity
            last_times = st.session_state.last_txn_time.get(user_key, [])
            one_min_ago = now - timedelta(minutes=1)
            last_times = [t for t in last_times if t > one_min_ago]
            velocity = len(last_times) + 1
            
            # Enhanced fraud detection logic
            bin_expected = str(allowed_countries[country]['bin'])
            fraud = 0
            suspicious = 0
            error_msg = ""
            
            # BIN validation
            if not from_acc.startswith(bin_expected) or len(from_acc) < 10:
                error_msg = f"🚨 FRAUD DETECTED: Account {from_acc[:4]}**** doesn't match {country} BIN pattern"
                fraud = 1
                
            # Velocity checks
            elif velocity >= 6:
                error_msg = f"🚨 FRAUD DETECTED: Excessive velocity ({velocity} txn/min) - Account blocked"
                fraud = 1
                
            elif velocity >= 4:
                error_msg = f"⚠️ SUSPICIOUS ACTIVITY: High velocity ({velocity} txn/min) detected"
                suspicious = 1
                
            # Amount-based checks
            elif amount > 50000 and country in ['Nigeria', 'Russia', 'Brazil']:
                error_msg = f"⚠️ SUSPICIOUS: Large amount ({amount:,.2f}) from high-risk country"
                suspicious = 1
                
            # VPN + High amount
            elif vpn and amount > 20000:
                error_msg = f"⚠️ SUSPICIOUS: VPN usage with high amount transaction"
                suspicious = 1
                
            else:
                error_msg = "✅ Transaction processed successfully"
                last_times.append(now)
                st.session_state.last_txn_time[user_key] = last_times
            
            # Calculate risk score
            risk_score = calculate_risk_score({
                'amount': amount,
                'velocity': velocity,
                'vpn': vpn,
                'country': country
            })
            
            # Save to database
            transaction_id = f"TXN{random.randint(100000, 999999)}"
            transaction_data = (
                transaction_id,
                st.session_state.current_user,
                from_acc,
                to_acc,
                receiver_email,
                country,
                amount,
                velocity,
                vpn,
                fraud,
                suspicious,
                risk_score,
                error_msg,
                f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",  # Mock IP
                f"FP{random.randint(1000,9999)}",  # Mock device fingerprint
                transaction_type,
                merchant_category
            )
            
            add_transaction_db(transaction_data)
            update_daily_kpis()
            
            # Send email notification to receiver
            transaction_details = {
                'transaction_id': transaction_id,
                'sender': st.session_state.current_user,
                'amount': amount,
                'country': country
            }
            
            with st.spinner("Processing transaction and sending notifications..."):
                email_sent = send_transaction_email(
                    receiver_email, 
                    transaction_details, 
                    is_fraud=bool(fraud), 
                    is_suspicious=bool(suspicious)
                )
            
            # Display result
            if fraud:
                st.markdown(f'<div class="fraud-alert">🚨 {error_msg}</div>', unsafe_allow_html=True)
            elif suspicious:
                st.markdown(f'<div class="suspicious-alert">⚠️ {error_msg}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="success-alert">✅ {error_msg}</div>', unsafe_allow_html=True)
            
            # Show transaction details
            st.success(f"📋 Transaction ID: {transaction_id}")
            st.info(f"🎯 Risk Score: {risk_score:.2f}/1.0")
            
            # Email status
            if email_sent:
                st.markdown('<div class="email-status email-success">📧 Email notification sent to receiver!</div>', unsafe_allow_html=True)
                st.info(f"✉️ Notification sent to: **{receiver_email}**")
            else:
                st.markdown('<div class="email-status email-error">❌ Failed to send email notification</div>', unsafe_allow_html=True)
                
    st.markdown('</div>', unsafe_allow_html=True)

# History Page
elif menu == "📜 History":
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.header("📋 Transaction History")
    
    df = get_transactions_db(st.session_state.user_role, st.session_state.current_user)
    
    if len(df) == 0:
        st.info("📝 No transactions found.")
    else:
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Transactions", len(df))
        with col2:
            fraud_count = df['fraud'].sum()
            st.metric("Fraud Cases", fraud_count, delta=f"{fraud_count/len(df)*100:.1f}%")
        with col3:
            suspicious_count = df['suspicious'].sum()
            st.metric("Suspicious Cases", suspicious_count, delta=f"{suspicious_count/len(df)*100:.1f}%")
        with col4:
            avg_amount = df['amount'].mean()
            st.metric("Avg Amount", f"₹{avg_amount:,.2f}")
        
        # Filters
        st.subheader("🔍 Filter Transactions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status_filter = st.selectbox("Status", ["All", "Fraud", "Suspicious", "Genuine"])
        with col2:
            country_filter = st.selectbox("Country", ["All"] + list(df['country'].unique()))
        with col3:
            date_range = st.date_input("Date Range", value=[datetime.now().date() - timedelta(days=30), datetime.now().date()])
        
        # Apply filters
        filtered_df = df.copy()
        
        if status_filter == "Fraud":
            filtered_df = filtered_df[filtered_df['fraud'] == 1]
        elif status_filter == "Suspicious":
            filtered_df = filtered_df[filtered_df['suspicious'] == 1]
        elif status_filter == "Genuine":
            filtered_df = filtered_df[(filtered_df['fraud'] == 0) & (filtered_df['suspicious'] == 0)]
        
        if country_filter != "All":
            filtered_df = filtered_df[filtered_df['country'] == country_filter]
        
        # Add status column for display
        def get_status(row):
            if row['fraud'] == 1:
                return "🚨 FRAUD"
            elif row['suspicious'] == 1:
                return "⚠️ SUSPICIOUS"
            else:
                return "✅ GENUINE"
        
        filtered_df['Status'] = filtered_df.apply(get_status, axis=1)
        
        # Display table
        display_columns = ['transaction_id', 'timestamp', 'sender', 'receiver_email', 'country', 'amount', 
                          'velocity', 'risk_score', 'Status', 'error']
        st.dataframe(
            filtered_df[display_columns],
            use_container_width=True,
            hide_index=True
        )
    
    st.markdown('</div>', unsafe_allow_html=True)

# Dashboard Page  
elif menu == "📊 Dashboard":
    st.header("📊 Fraud Detection Dashboard")
    
    df = get_transactions_db(st.session_state.user_role, st.session_state.current_user)
    
    if len(df) == 0:
        st.info("📝 No transaction data available for analysis.")
    else:
        # Key Metrics Row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_txns = len(df)
        fraud_txns = df['fraud'].sum()
        suspicious_txns = df['suspicious'].sum()
        fraud_rate = (fraud_txns / total_txns * 100) if total_txns > 0 else 0
        avg_risk_score = df['risk_score'].mean()
        
        with col1:
            st.metric("Total Transactions", f"{total_txns:,}")
        with col2:
            st.metric("Fraud Cases", fraud_txns, delta=f"{fraud_rate:.1f}%")
        with col3:
            st.metric("Suspicious Cases", suspicious_txns)
        with col4:
            st.metric("Avg Risk Score", f"{avg_risk_score:.3f}")
        with col5:
            genuine_rate = ((total_txns - fraud_txns - suspicious_txns) / total_txns * 100) if total_txns > 0 else 0
            st.metric("Success Rate", f"{genuine_rate:.1f}%")
        
        # Charts Row 1
        col1, col2 = st.columns(2)
        
        with col1:
            # Fraud Distribution Pie Chart
            fraud_data = pd.DataFrame({
                'Status': ['Genuine', 'Fraud', 'Suspicious'],
                'Count': [
                    total_txns - fraud_txns - suspicious_txns,
                    fraud_txns,
                    suspicious_txns
                ]
            })
            
            fig_pie = px.pie(
                fraud_data, 
                values='Count', 
                names='Status',
                title='Transaction Status Distribution',
                color_discrete_map={
                    'Genuine': '#10b981',
                    'Fraud': '#ef4444', 
                    'Suspicious': '#f59e0b'
                }
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Fraud by Country
            country_stats = df.groupby('country').agg({
                'fraud': 'sum',
                'suspicious': 'sum',
                'transaction_id': 'count'
            }).reset_index()
            country_stats.columns = ['Country', 'Fraud', 'Suspicious', 'Total']
            country_stats['Fraud_Rate'] = (country_stats['Fraud'] / country_stats['Total'] * 100).round(2)
            
            fig_country = px.bar(
                country_stats.head(10),
                x='Country',
                y=['Fraud', 'Suspicious'],
                title='Fraud Cases by Country',
                color_discrete_map={'Fraud': '#ef4444', 'Suspicious': '#f59e0b'}
            )
            st.plotly_chart(fig_country, use_container_width=True)
        
        # Charts Row 2
        col1, col2 = st.columns(2)
        
        with col1:
            # Transaction Amount vs Risk Score
            fig_scatter = px.scatter(
                df,
                x='amount',
                y='risk_score',
                color='fraud',
                title='Transaction Amount vs Risk Score',
                labels={'amount': 'Transaction Amount (₹)', 'risk_score': 'Risk Score'},
                color_discrete_map={0: '#10b981', 1: '#ef4444'}
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
        
        with col2:
            # Velocity Analysis
            velocity_stats = df.groupby('velocity').agg({
                'fraud': 'sum',
                'transaction_id': 'count'
            }).reset_index()
            velocity_stats['fraud_rate'] = (velocity_stats['fraud'] / velocity_stats['transaction_id'] * 100).round(2)
            
            fig_velocity = px.line(
                velocity_stats,
                x='velocity',
                y='fraud_rate',
                title='Fraud Rate by Transaction Velocity',
                labels={'velocity': 'Transactions per Minute', 'fraud_rate': 'Fraud Rate (%)'},
                markers=True
            )
            st.plotly_chart(fig_velocity, use_container_width=True)
        
        # Time Series Analysis
        st.subheader("📈 Fraud Trends Over Time")
        
        # Create hourly analysis
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        hourly_stats = df.groupby('hour').agg({
            'fraud': 'sum',
            'suspicious': 'sum',
            'transaction_id': 'count'
        }).reset_index()
        
        fig_hourly = go.Figure()
        fig_hourly.add_trace(go.Bar(
            x=hourly_stats['hour'],
            y=hourly_stats['fraud'],
            name='Fraud',
            marker_color='#ef4444'
        ))
        fig_hourly.add_trace(go.Bar(
            x=hourly_stats['hour'],
            y=hourly_stats['suspicious'],
            name='Suspicious',
            marker_color='#f59e0b'
        ))
        
        fig_hourly.update_layout(
            title='Fraud Activity by Hour of Day',
            xaxis_title='Hour of Day',
            yaxis_title='Number of Cases',
            barmode='stack'
        )
        
        st.plotly_chart(fig_hourly, use_container_width=True)

# Analytics Page
elif menu == "🔍 Analytics":
    st.header("🔬 Advanced Fraud Analytics")
    
    df = get_transactions_db(st.session_state.user_role, st.session_state.current_user)
    
    if len(df) == 0:
        st.info("📝 No data available for analysis.")
    else:
        # KPI Cards
        st.subheader("📊 Key Performance Indicators (KPIs)")
        
        # Calculate advanced KPIs
        total_transactions = len(df)
        fraud_transactions = df['fraud'].sum()
        suspicious_transactions = df['suspicious'].sum()
        
        # Fraud Detection Rate
        fraud_detection_rate = (fraud_transactions / total_transactions * 100) if total_transactions > 0 else 0
        
        # False Positive Rate (assuming suspicious are potential false positives)
        false_positive_rate = (suspicious_transactions / total_transactions * 100) if total_transactions > 0 else 0
        
        # Average Risk Score
        avg_risk_score = df['risk_score'].mean()
        
        # Total Amount at Risk
        fraud_amount = df[df['fraud'] == 1]['amount'].sum()
        total_amount = df['amount'].sum()
        amount_at_risk = (fraud_amount / total_amount * 100) if total_amount > 0 else 0
        
        # Create KPI layout
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
                <div class="kpi-box">
                    <h3 style="color: #ef4444;">🎯 Fraud Detection Rate</h3>
                    <h2 style="color: #1f2937;">{fraud_detection_rate:.2f}%</h2>
                    <p style="color: #6b7280;">Cases detected: {fraud_transactions}</p>
                </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
                <div class="kpi-box">
                    <h3 style="color: #f59e0b;">⚠️ False Positive Rate</h3>
                    <h2 style="color: #1f2937;">{false_positive_rate:.2f}%</h2>
                    <p style="color: #6b7280;">Suspicious: {suspicious_transactions}</p>
                </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
                <div class="kpi-box">
                    <h3 style="color: #8b5cf6;">📊 Avg Risk Score</h3>
                    <h2 style="color: #1f2937;">{avg_risk_score:.3f}</h2>
                    <p style="color: #6b7280;">Scale: 0.0 - 1.0</p>
                </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown(f"""
                <div class="kpi-box">
                    <h3 style="color: #ef4444;">💰 Amount at Risk</h3>
                    <h2 style="color: #1f2937;">{amount_at_risk:.2f}%</h2>
                    <p style="color: #6b7280;">₹{fraud_amount:,.2f}</p>
                </div>
            """, unsafe_allow_html=True)
        
        # Advanced Analysis Sections
        st.subheader("🔍 Pattern Analysis")
        
        # Risk Score Distribution
        col1, col2 = st.columns(2)
        
        with col1:
            fig_risk_dist = px.histogram(
                df,
                x='risk_score',
                nbins=20,
                title='Risk Score Distribution',
                labels={'risk_score': 'Risk Score', 'count': 'Frequency'},
                color_discrete_sequence=['#3b82f6']
            )
            st.plotly_chart(fig_risk_dist, use_container_width=True)
        
        with col2:
            # Transaction Type Analysis
            type_stats = df.groupby('transaction_type').agg({
                'fraud': 'sum',
                'transaction_id': 'count'
            }).reset_index()
            type_stats['fraud_rate'] = (type_stats['fraud'] / type_stats['transaction_id'] * 100).round(2)
            
            fig_type = px.bar(
                type_stats,
                x='transaction_type',
                y='fraud_rate',
                title='Fraud Rate by Transaction Type',
                labels={'transaction_type': 'Transaction Type', 'fraud_rate': 'Fraud Rate (%)'},
                color='fraud_rate',
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig_type, use_container_width=True)
        
        # Correlation Analysis
        st.subheader("📈 Correlation Analysis")
        
        # Select numeric columns for correlation
        numeric_cols = ['amount', 'velocity', 'vpn', 'fraud', 'suspicious', 'risk_score']
        correlation_data = df[numeric_cols].corr()
        
        fig_corr = px.imshow(
            correlation_data,
            text_auto=True,
            aspect="auto",
            title="Feature Correlation Matrix",
            color_continuous_scale='RdBu'
        )
        st.plotly_chart(fig_corr, use_container_width=True)
        
        # Anomaly Detection using Isolation Forest
        st.subheader("🔍 ML-Based Anomaly Detection")
        
        if st.button("🤖 Run Isolation Forest Analysis"):
            # Prepare data for anomaly detection
            features = ['amount', 'velocity', 'vpn', 'risk_score']
            X = df[features].fillna(0)
            
            # Standardize features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Apply Isolation Forest
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_pred = iso_forest.fit_predict(X_scaled)
            
            # Add predictions to dataframe
            df_anomaly = df.copy()
            df_anomaly['anomaly'] = anomaly_pred
            df_anomaly['anomaly_label'] = df_anomaly['anomaly'].map({1: 'Normal', -1: 'Anomaly'})
            
            # Show results
            anomaly_count = (anomaly_pred == -1).sum()
            st.success(f"✅ Analysis complete! Detected {anomaly_count} anomalies out of {len(df)} transactions.")
            
            # Visualize anomalies
            fig_anomaly = px.scatter(
                df_anomaly,
                x='amount',
                y='risk_score',
                color='anomaly_label',
                title='ML-Detected Anomalies',
                labels={'amount': 'Transaction Amount', 'risk_score': 'Risk Score'},
                color_discrete_map={'Normal': '#10b981', 'Anomaly': '#ef4444'}
            )
            st.plotly_chart(fig_anomaly, use_container_width=True)
            
            # Show anomaly details
            anomalies_df = df_anomaly[df_anomaly['anomaly'] == -1][['transaction_id', 'amount', 'velocity', 'risk_score', 'country', 'fraud']]
            st.subheader("🚨 Detected Anomalies")
            st.dataframe(anomalies_df, use_container_width=True)

# User Management Page
elif menu == "👥 User Management":
    st.header("👥 User Management")
    
    if st.session_state.user_role == "Admin":
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        
        # Get all users
        users_df = get_all_users_db()
        
        st.subheader("📊 User Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        total_users = len(users_df)
        admin_users = len(users_df[users_df['role'] == 'Admin'])
        regular_users = len(users_df[users_df['role'] == 'User'])
        
        with col1:
            st.metric("Total Users", total_users)
        with col2:
            st.metric("Admin Users", admin_users)
        with col3:
            st.metric("Regular Users", regular_users)
        with col4:
            st.metric("Active Sessions", "1")  # Current logged in users
        
        # Users table
        st.subheader("👤 All System Users")
        
        # Add status indicators
        users_df['Status'] = users_df.apply(
            lambda row: "👑 ADMIN" if row['role'] == 'Admin' else "👤 USER", axis=1
        )
        
        st.dataframe(
            users_df[['username', 'email', 'Status', 'created_at']],
            use_container_width=True,
            hide_index=True
        )
        
        # Show predefined vs new users
        st.subheader("📋 User Categories")
        
        predefined_usernames = ['admin', 'john_doe', 'alice_smith', 'bob_johnson', 'sarah_wilson', 
                               'mike_brown', 'emma_davis', 'david_miller', 'lisa_garcia', 
                               'tom_anderson', 'jennifer_taylor', 'michael_clark', 'jessica_lewis', 
                               'ryan_walker', 'amanda_hall', 'chris_young', 'supervisor', 
                               'manager', 'analyst', 'demo_user']
        
        predefined_users = users_df[users_df['username'].isin(predefined_usernames)]
        new_users = users_df[~users_df['username'].isin(predefined_usernames)]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info(f"🔧 **Predefined Users:** {len(predefined_users)}")
            if len(predefined_users) > 0:
                st.dataframe(
                    predefined_users[['username', 'role']].head(10),
                    use_container_width=True,
                    hide_index=True
                )
        
        with col2:
            st.success(f"🆕 **New Registered Users:** {len(new_users)}")
            if len(new_users) > 0:
                st.dataframe(
                    new_users[['username', 'email', 'role', 'created_at']],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No new users registered yet.")
        
        st.markdown('</div>', unsafe_allow_html=True)
        
    else:
        st.warning("⚠️ Admin access required for user management.")

# Admin Panel
elif menu == "⚙️ Admin Panel" and st.session_state.user_role == "Admin":
    st.header("⚙️ System Administration")
    
    # System Overview
    conn = sqlite3.connect(DATABASE_PATH)
    
    # Get system statistics
    total_users = pd.read_sql_query("SELECT COUNT(*) as count FROM users", conn).iloc[0]['count']
    total_transactions = pd.read_sql_query("SELECT COUNT(*) as count FROM transactions", conn).iloc[0]['count']
    total_fraud = pd.read_sql_query("SELECT COUNT(*) as count FROM transactions WHERE fraud = 1", conn).iloc[0]['count']
    
    conn.close()
    
    # System metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("👥 Total Users", total_users)
    with col2:
        st.metric("💳 Total Transactions", f"{total_transactions:,}")
    with col3:
        st.metric("🚨 Fraud Cases", total_fraud)
    with col4:
        system_health = "🟢 Healthy" if total_fraud / max(total_transactions, 1) < 0.05 else "🟡 Monitoring"
        st.metric("🏥 System Health", system_health)
    
    # Admin actions
    st.subheader("🔧 Admin Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export Transaction Data"):
            df = get_transactions_db("Admin")
            csv = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv,
                file_name=f"transactions_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col2:
        if st.button("📥 Export User Data"):
            users_df = get_all_users_db()
            csv = users_df.to_csv(index=False)
            st.download_button(
                label="⬇️ Download Users CSV",
                data=csv,
                file_name=f"users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col3:
        if st.button("🔄 Update KPIs"):
            update_daily_kpis()
            st.success("✅ KPIs updated successfully!")
    
    # Recent fraud cases
    st.subheader("🚨 Recent Fraud Cases")
    df = get_transactions_db("Admin")
    if len(df) > 0:
        recent_fraud = df[(df['fraud'] == 1)].head(10)
        if len(recent_fraud) > 0:
            st.dataframe(
                recent_fraud[['transaction_id', 'timestamp', 'sender', 'amount', 'country', 'error']],
                use_container_width=True
            )
        else:
            st.info("No recent fraud cases.")
    else:
        st.info("No transaction data available.")

elif menu == "⚙️ Admin Panel":
    st.warning("⚠️ Admin access required for this section.")

# Logout option in sidebar
if st.session_state.logged_in:
    st.sidebar.markdown("---")
    st.sidebar.info(f"👤 Logged in as: **{st.session_state.current_user}**")
    st.sidebar.info(f"📧 Email: **{st.session_state.user_email}**")
    if st.sidebar.button("🚪 Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
