import ccxt
import pandas as pd
import getpass
from cryptography.fernet import Fernet
import os
import schedule
import time
import logging
import hashlib
import subprocess
import sys
import matplotlib.pyplot as plt

# Configuration Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the password hash (SHA-256 hash of "ned/1777/07-08")
PASSWORD_HASH = "7a2288ff7a04544c1a3b8948ca36264ae4acafbf2b8109b06c19b4476fcb5659"

def check_password():
    """Prompt for password and check against stored hash."""
    password = getpass.getpass("Enter password to start the bot: ")
    if not verify_password(password, PASSWORD_HASH):
        logging.error("Incorrect password. Exiting.")
        exit()

def verify_password(password, hashed_password):
    """Verify password against the stored hash."""
    hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_input_password == hashed_password

def load_keys():
    """Load and decrypt API keys."""
    key_file = "encryption.key"
    config_file = "config.enc"

    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        logging.info("Encryption key generated and saved.")
    else:
        with open(key_file, "rb") as f:
            key = f.read()

    if not os.path.exists(config_file):
        api_key = getpass.getpass("Enter your Binance API Key: ")
        secret_key = getpass.getpass("Enter your Binance Secret Key: ")
        cipher_suite = Fernet(key)
        encrypted_api_key = cipher_suite.encrypt(api_key.encode())
        encrypted_secret_key = cipher_suite.encrypt(secret_key.encode())
        with open(config_file, "wb") as f:
            f.write(encrypted_api_key + b"\n" + encrypted_secret_key)
        logging.info("API keys encrypted and saved.")
    else:
        with open(config_file, "rb") as f:
            encrypted_data = f.read().split(b"\n")
            cipher_suite = Fernet(key)
            api_key = cipher_suite.decrypt(encrypted_data[0]).decode()
            secret_key = cipher_suite.decrypt(encrypted_data[1]).decode()

    return api_key, secret_key

def initialize_binance(api_key, secret_key):
    """Initialize the Binance exchange with API keys."""
    exchange = ccxt.binance({
        'apiKey': api_key,
        'secret': secret_key,
        'enableRateLimit': True,
    })
    logging.info("Binance exchange initialized.")
    return exchange

def trading_logic(exchange):
    """Execute trading strategy and save reports."""
    try:
        symbols = ['ETH/USDT', 'BNB/USDT', 'BTC/USDT', 'SOL/USDT', 'SUI/USDT']
        trading_data = []
        for symbol in symbols:
            ticker = exchange.fetch_ticker(symbol)
            balance = exchange.fetch_balance()
            trading_data.append({
                'symbol': symbol,
                'price': ticker['last'],
                'balance': balance['total']['USDT']
            })
            logging.info(f"Ticker for {symbol}: {ticker}")
            logging.info(f"Current Balance: {balance}")

            # Example Trading Strategy
            price_threshold = 2000  # Example threshold price
            if ticker['last'] < price_threshold:
                amount_to_buy = 0.1  # Example amount to buy
                order = exchange.create_market_buy_order(symbol, amount_to_buy)
                logging.info(f"Buy Order: {order}")

        save_report(trading_data)
        suggest_actions(exchange)
        
    except Exception as e:
        logging.error(f"Error in trading logic: {e}")

def save_report(trading_data):
    """Generate and save a report based on trading data."""
    df = pd.DataFrame(trading_data)
    report_file = "reports/trading_report.csv"
    df.to_csv(report_file, index=False)
    logging.info(f"Report saved to {report_file}")

    # Create a graphical summary
    plt.figure(figsize=(12, 8))
    for symbol in df['symbol'].unique():
        symbol_data = df[df['symbol'] == symbol]
        plt.plot(symbol_data.index, symbol_data['price'], marker='o', label=symbol)
    plt.title('Price Trends')
    plt.xlabel('Index')
    plt.ylabel('Price (USDT)')
    plt.legend()
    plt.grid(True)
    plt.savefig("reports/price_trends.png")
    plt.show()
    logging.info("Graphical summary saved as reports/price_trends.png")

def manage_profits(exchange):
    """Manage profits based on trading performance."""
    try:
        logging.info("Managing profits...")
        # Implement profit management logic here
    except Exception as e:
        logging.error(f"Error in profit management: {e}")

def update_code():
    """Pull the latest code from the repository and restart the bot."""
    logging.info("Checking for updates...")
    try:
        # Pull the latest code from the GitHub repository
        result = subprocess.run(['git', 'pull'], capture_output=True, text=True)
        if "Already up to date." in result.stdout:
            logging.info("Bot is already up to date.")
        else:
            logging.info("Code updated successfully.")
            # Restart the bot
            logging.info("Restarting bot...")
            python = sys.executable
            os.execv(python, [python] + sys.argv)
    except Exception as e:
        logging.error(f"Error updating code: {e}")

def suggest_actions(exchange):
    """Suggest deposit or withdrawal actions based on account performance."""
    try:
        balance = exchange.fetch_balance()
        total_balance = balance['total']['USDT']
        logging.info(f"Current Total Balance: {total_balance}")

        # Example criteria for suggestions
        if total_balance < 50:
            logging.info("Suggestion: Consider depositing more funds.")
        elif total_balance > 1000:
            logging.info("Suggestion: Consider withdrawing excess funds.")
    except Exception as e:
        logging.error(f"Error in suggestions: {e}")

def main():
    update_code()  # Check for updates before starting
    check_password()  # Check password before starting the bot
    api_key, secret_key = load_keys()
    exchange = initialize_binance(api_key, secret_key)

    # Schedule tasks
    schedule.every().hour.do(lambda: trading_logic(exchange))
    schedule.every().day.do(lambda: manage_profits(exchange))

    logging.info("Bot started. Monitoring and trading...")
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
