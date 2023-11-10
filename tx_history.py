from js import window, document, alert, prompt, Blob
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
from address import Address
from datetime import datetime
from typing import List
from panel.io.pyodide import show
import panel as pn
import pandas as pd
import asyncio
import time


document.querySelector('#wait-package-loading').remove()

# Enable Nami
nami = window.cardano.nami

async def enable_nami(*args):
    global nami_api
    nami_api = await nami.enable()
    h3_ele = document.querySelector('#wallet')
    h3_ele.innerText = f'Wallet enabled: True'

enable_wallet_btn = document.querySelector('#enable-wallet-btn')
enable_wallet_btn.addEventListener('click', create_proxy(enable_nami))
if await nami.isEnabled():
    enable_wallet_btn.click()
        

# BlockFrost
BLOCKFROST_URL = 'https://cardano-mainnet.blockfrost.io/api/v0'
API_KEY = {}


async def add_api_key(*args) -> None:
    API_KEY.clear()
    if not await nami.isEnabled():
        alert('Enable Nami wallet first')
        return
    api_key = prompt('Enter BlockFrost API key (mainnet)')
    if api_key is None:
        return
    if not api_key.startswith('mainnet') or len(api_key) != 39:
        alert('Wrong key')
        return
    API_KEY['project_id'] = api_key


async def fetch_txs(*args) -> None:
    if not await nami.isEnabled():
        alert('Enable Nami wallet first')
        return
    if not API_KEY.get('project_id'):
        alert('Add a BlockFrost API key (mainnet)')
        return
    
    document.querySelector('#wait-txs').innerHTML = '<h4>Fetching transactions...This may take a while...</h4>'
    spinner = document.querySelector('#spinner')
    spinner.style.display = 'block'

    bech32_addr = str(Address.from_primitive(bytes.fromhex((await nami_api.getUsedAddresses())[0])))
    fetched_all_txs = False
    txs = []
    i = 1
    while not fetched_all_txs:
        r = await pyfetch(
            url = f'{BLOCKFROST_URL}/addresses/{bech32_addr}/transactions?page={i}',
            method = 'GET',
            headers = API_KEY
        )
        data = await r.json()
        if len(data) == 0:
            fetched_all_txs = True
        txs.extend(data)
        i += 1
        time.sleep(1)
        print("slept 1s")

    data = [await tx_info(tx['tx_hash'], bech32_addr) for tx in txs]
    
    document.querySelector('#wait-txs').innerHTML = ''
    spinner.style.display = 'none'

    df = await show_table(data)

    export_csv_link = document.querySelector('#export-csv-link')
    export_csv_link.style.display = 'inline-block'
    export_csv_link.addEventListener('click', create_proxy(export_to_csv(df, export_csv_link)))

                    
async def tx_info(tx_hash: str, addr: str) -> tuple:
    try:
        res1 = await pyfetch(
            url = f'{BLOCKFROST_URL}/txs/{tx_hash}',
            method = 'GET',
            headers = API_KEY
        )
        res2 = await pyfetch(
            url = f'{BLOCKFROST_URL}/txs/{tx_hash}/utxos',
            method = 'GET',
            headers = API_KEY
        )
        time.sleep(0.5)
        print('slept 0.5s...')
    except Exception as e:
        document.querySelector('#wait-txs').innerHTML = '<h4 style="color: red;">Error encountered when fetching txs from BlockFrost, retry after a minute.</h4>'
        spinner = document.querySelector('#spinner')
        spinner.style.display = 'none'
        raise e
    else:
        tx_details = await res1.json()
        slot = tx_details['slot']
        date = date_from_slot(slot)  # UTC
        fees = int(tx_details['fees'])
        utxos = await res2.json()
        utxos = utxos['inputs'] + utxos['outputs']
    
    inputs_sum = 0
    outputs_sum = 0
    for utxo in utxos:
        if utxo.get('collateral'):
            continue
        if utxo['address'] == addr:
            for item in utxo['amount']:
                if item['unit'] == 'lovelace':
                    if 'tx_hash' in utxo:
                        inputs_sum += int(item['quantity'])
                    else:
                        outputs_sum += int(item['quantity'])
    net_sum = outputs_sum + fees - inputs_sum
    if net_sum == 0:
        tx_type = 'Self'
    elif net_sum < 0:
        tx_type = 'Send'
        net_sum = round((inputs_sum - outputs_sum)/1e6, 2)
    elif net_sum > 0:
        tx_type = 'Receive'
        net_sum = round((net_sum - fees)/1e6, 2)
    
    return (tx_hash, tx_type, net_sum, date)


def date_from_slot(slot: int) -> str:
    shelley_unix = 1596491091
    shelley_slot = 4924800
    timestamp = shelley_unix + (slot - shelley_slot)
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    
async def show_table(data: List[tuple]) -> pd.DataFrame:
    df = pd.DataFrame(data, columns=['TxId', 'Type', 'Amount', 'Date (UTC)'])
    table = pn.widgets.Tabulator(value=df, pagination='remote')
    await show(table, 'table')
    return df
    

def export_to_csv(df, export_csv_link) -> None:
    export_csv_link.href = window.URL.createObjectURL(Blob.new([df.to_csv(index=False)]), { type: 'text/plain' })
    export_csv_link.download = 'tx_history.csv'
    

api_key_btn = document.querySelector('#api-key-btn')
api_key_btn.addEventListener('click', create_proxy(add_api_key))
show_txs_btn = document.querySelector('#show-txs-btn')
show_txs_btn.addEventListener('click', create_proxy(fetch_txs))
