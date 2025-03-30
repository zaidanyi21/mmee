import requests
from twocaptcha import TwoCaptcha
from colorama import init, Fore, Style
from datetime import datetime
import pytz
import threading
from tzlocal import get_localzone
from concurrent.futures import ThreadPoolExecutor, as_completed
from web3 import Web3
from decimal import Decimal
import secrets
import time

init(autoreset=True)

# ================== CONFIG ==================
THREADS = 5
TWO_CAPTCHA_API_KEY = "API_TWOCAPTCHA"
RECIPIENT_ADDRESS = "ADDRESS_TUJUAN"
NUMBER_OF_WALLETS = 5  # Number of wallets per iteration

TURNSTILE_SITEKEY = "0x4AAAAAABA4JXCaw9E2Py-9"
TURNSTILE_PAGE_URL = "https://testnet.megaeth.com/"
MEGAETH_API_URL = "https://carrot.megaeth.com/claim"
MEGAETH_RPC_URL = "https://carrot.megaeth.com/rpc"

SUCCESS_FILE = "success.txt"
FAIL_FILE = "fail.txt"
DELAY_BETWEEN_ITERATIONS = 5  # Delay in seconds between iterations

# Inisialisasi Web3
web3 = Web3(Web3.HTTPProvider(MEGAETH_RPC_URL))
chainId = web3.eth.chain_id
if not web3.is_connected():
    print("Failed to connect to MegaETH network")
    exit(1)

headers = {
    "Accept": "*/*",
    "Content-Type": "text/plain;charset=UTF-8",
    "Origin": "https://testnet.megaeth.com",
    "Referer": "https://testnet.megaeth.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
}

def now_local():
    local_tz = get_localzone()
    return datetime.now(local_tz).strftime("%H:%M:%S %d/%m/%Y")

def log_info(msg, idx=None):
    if idx is not None:
        print(f"{Fore.CYAN}[{now_local()}] [{idx}] {msg}{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[{now_local()}] {msg}{Style.RESET_ALL}")

def log_success(msg, idx=None):
    if idx is not None:
        print(f"{Fore.GREEN}[{now_local()}] [{idx}] {msg}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[{now_local()}] {msg}{Style.RESET_ALL}")

def log_fail(msg, idx=None):
    if idx is not None:
        print(f"{Fore.RED}[{now_local()}] [{idx}] {msg}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[{now_local()}] {msg}{Style.RESET_ALL}")

def generate_wallet():
    private_key = "0x" + secrets.token_hex(32)
    account = web3.eth.account.from_key(private_key)
    return account.address, private_key

def solve_turnstile(idx=None):
    try:
        solver = TwoCaptcha(TWO_CAPTCHA_API_KEY)
        result = solver.solve(
            method='turnstile',
            sitekey=TURNSTILE_SITEKEY,
            url=TURNSTILE_PAGE_URL
        )
        token = result.get("code")
        if token:
            log_success("Turnstile solved OK", idx=idx)
            return token
        else:
            log_fail(f"Turnstile solve got invalid response: {result}", idx=idx)
            return None
    except Exception as e:
        log_fail(f"Turnstile solve error: {e}", idx=idx)
        return None

def megaeth_claim(wallet, token, idx=None):
    try:
        resp = requests.post(
            MEGAETH_API_URL,
            json={"addr": wallet, "token": token},
            headers=headers,
            timeout=60
        )
        return resp.json()
    except Exception as e:
        log_fail(f"Claim API error for {wallet}: {e}", idx=idx)
        return None

def send_all_ether(sender_address, sender_private_key, recipient_address, idx=None):
    try:
        balance = web3.eth.get_balance(sender_address)
        log_info(f"Sender balance: {balance} wei ({web3.from_wei(balance, 'ether')} ETH)", idx=idx)
        
        # Get current gas price with a 1.5x buffer
        gas_price = int(web3.eth.gas_price * Decimal('1.5'))
        log_info(f"Gas price: {gas_price} wei ({web3.from_wei(gas_price, 'gwei')} Gwei)", idx=idx)
        
        # Dynamically estimate gas
        temp_tx = {
            'to': recipient_address,
            'value': balance,
            'from': sender_address
        }
        gas_limit = web3.eth.estimate_gas(temp_tx)
        log_info(f"Estimated gas limit: {gas_limit}", idx=idx)
        
        gas_cost = gas_limit * gas_price
        log_info(f"Gas cost: {gas_cost} wei ({web3.from_wei(gas_cost, 'ether')} ETH)", idx=idx)
        
        if balance <= gas_cost:
            log_fail(f"Insufficient balance to cover gas: {balance} wei vs {gas_cost} wei", idx=idx)
            return False
        
        # Add a small buffer (10% more gas) to ensure success
        gas_cost_with_buffer = int(gas_cost * Decimal('1.1'))
        amount_to_send = balance - gas_cost_with_buffer
        log_info(f"Amount to send (with buffer): {amount_to_send} wei ({web3.from_wei(amount_to_send, 'ether')} ETH)", idx=idx)
        
        if amount_to_send <= 0:
            log_fail(f"Not enough balance to send after gas: {balance} wei", idx=idx)
            return False
        
        transaction = {
            'to': recipient_address,
            'value': amount_to_send,
            'gas': gas_limit,
            'maxFeePerGas': gas_price,
            'maxPriorityFeePerGas': gas_price,
            'nonce': web3.eth.get_transaction_count(sender_address),
            'chainId': chainId
        }
        
        log_info(f"Processing send {amount_to_send} wei ({web3.from_wei(amount_to_send, 'ether')} ETH) to {recipient_address}", idx=idx)
        tx_hash = web3.eth.send_raw_transaction(
            web3.eth.account.sign_transaction(transaction, sender_private_key).rawTransaction
        )
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        log_success(f"Transaction sent! Tx Hash: {web3.to_hex(tx_hash)}", idx=idx)
        return True
    except Exception as e:
        log_fail(f"Error while sending ETH: {e}", idx=idx)
        return False

def process_wallet(wallet_data, index, stop_event):
    wallet, private_key = wallet_data
    log_info(f"Claiming for address: {wallet}", idx=index)
    max_retries = 3
    attempts = 0
    success_flag = False

    while attempts < max_retries and not success_flag:
        if stop_event.is_set():
            log_info("Stop event detected. Exiting thread.", idx=index)
            return

        turnstile_token = solve_turnstile(idx=index)
        if not turnstile_token:
            log_fail("Turnstile solve failed", idx=index)
            attempts += 1
            continue

        resp = megaeth_claim(wallet, turnstile_token, idx=index)
        if resp:
            log_info(f"Claim response: {resp}", idx=index)
            if resp.get("success", False) and resp.get("txhash", ""):
                success_flag = True
            else:
                log_fail("Claim not successful, will retry...", idx=index)
        else:
            log_fail("Claim returned None, will retry...", idx=index)

        attempts += 1

    if success_flag:
        log_success(f"Claim SUCCESS for wallet {wallet}", idx=index)
        with open(SUCCESS_FILE, "a") as f:
            f.write(f"{wallet}|{private_key}\n")
        
        if send_all_ether(wallet, private_key, RECIPIENT_ADDRESS, idx=index):
            log_success(f"ETH transfer to {RECIPIENT_ADDRESS} successful!", idx=index)
        else:
            log_fail(f"ETH transfer to {RECIPIENT_ADDRESS} failed!", idx=index)
    else:
        log_fail(f"Claim FAILED after {max_retries} attempts for {wallet}", idx=index)
        with open(FAIL_FILE, "a") as f:
            f.write(f"{wallet}|{private_key}\n")

def main(stop_event):
    log_info(f"Starting unlimited faucet claim loop with {THREADS} threads...", idx=0)
    log_info(f"Recipient address: {RECIPIENT_ADDRESS}", idx=0)
    
    iteration = 1
    while True:  # Unlimited loop
        if stop_event.is_set():
            log_info("Stop event detected. Exiting loop...", idx=0)
            break
        
        log_info(f"Iteration {iteration}: Generating {NUMBER_OF_WALLETS} wallets...", idx=0)
        
        # Generate wallets for this iteration
        wallets = [generate_wallet() for _ in range(NUMBER_OF_WALLETS)]

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(process_wallet, w, i, stop_event): w
                for i, w in enumerate(wallets, start=1)
            }
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                log_info("KeyboardInterrupt detected in main loop. Setting stop event...", idx=0)
                stop_event.set()
                for future in futures:
                    future.cancel()
                raise

        iteration += 1
        log_info(f"Completed iteration {iteration - 1}. Waiting {DELAY_BETWEEN_ITERATIONS} seconds before next iteration...", idx=0)
        time.sleep(DELAY_BETWEEN_ITERATIONS)  # Delay to avoid overwhelming the faucet

if __name__ == "__main__":
    stop_event = threading.Event()
    try:
        main(stop_event)
    except KeyboardInterrupt:
        log_info("User has stopped the program. Exiting...", idx=0)
