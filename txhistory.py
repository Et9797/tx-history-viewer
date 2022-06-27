from js import window, document, alert, prompt, Blob
from pyodide import create_proxy
from pyodide.http import pyfetch
from address import Address
from datetime import datetime
from typing import List
from math import ceil
from panel.io.pyodide import show
import panel as pn
import pandas as pd
import asyncio


document.querySelector("#wait-packages").remove()


# Enable Nami
nami = window.cardano.nami

async def enable_nami(*args):
    global nami_api
    nami_api = await nami.enable()
    h3_ele = document.querySelector("#wallet")
    h3_ele.innerText = f'Wallet enabled: True'

enable_wallet_btn = document.querySelector("#enable-wallet")
enable_wallet_btn.addEventListener('click', create_proxy(enable_nami))
if await nami.isEnabled():
    enable_wallet_btn.click()


# Blockfrost
BLOCKFROST_URL = 'https://cardano-mainnet.blockfrost.io/api/v0'
API_KEY = {}


async def add_api_key(*args):
    API_KEY.clear()
    if not await nami.isEnabled():
        alert("Enable Nami wallet first")
        return
    api_key = prompt("Enter Blockfrost API key (mainnet)")
    if api_key is None:
        return
    if not api_key.startswith("mainnet") or len(api_key) != 39:
        alert("Wrong key")
        return
    API_KEY["project_id"] = api_key


async def fetch_txs(*args):
    if not await nami.isEnabled():
        alert("Enable Nami wallet first")
        return
    if not API_KEY.get("project_id"):
        alert("Add Blockfrost API key")
        return
    
    pyscript.write('wait-txs', '<h4>Fetching transactions...</h4>')
    spinner = document.querySelector('#spinner')
    spinner.style.display = 'block'

    bech32_addr = str(
        Address.from_primitive(
            bytes.fromhex((await nami_api.getUsedAddresses())[0])
        )
    )
    i = 1
    fetched_all_txs = False
    txs = []
    while not fetched_all_txs:
        r = await pyfetch(
            url = f"{BLOCKFROST_URL}/addresses/{bech32_addr}/transactions?page={i}",
            method = "GET",
            headers = API_KEY
        )
        data = await r.json()
        if len(data) == 0:
            fetched_all_txs = True
        txs.extend(data)
        i += 1

    if len(txs) <= 50:
        tasks = [ asyncio.create_task(tx_info(tx['tx_hash'], bech32_addr)) for tx in txs ]
        data: List[tuple] = await asyncio.gather(*tasks)
    else:
        # split the txs list into bins of size 50 and wait 2s after each async call to reduce spamming
        nr_bins = ceil(len(txs) / 50)
        tasks = []
        data = []
        for i in range(nr_bins):
            for tx in txs[i*50:i*50+50]:
                tasks.append(
                    asyncio.create_task(tx_info(tx['tx_hash'], bech32_addr))
                )
            data.extend(await asyncio.gather(*tasks))
            tasks.clear()
            if i == nr_bins:
                break
            await asyncio.sleep(2)
        
    pyscript.write('wait-txs', '')
    spinner.style.display = 'none'

    df = await show_table(data)

    export_btn = document.querySelector("#export")
    export_btn.style.display = 'inline-block'
    export_btn.addEventListener('click', create_proxy(export_to_csv(df, export_btn)))

                    
async def tx_info(tx_hash: str, addr: str) -> tuple:
    try:
        res1 = await pyfetch(
            url = f"{BLOCKFROST_URL}/txs/{tx_hash}",
            method = "GET",
            headers = API_KEY
        )
        res2 = await pyfetch(
            url = f"{BLOCKFROST_URL}/txs/{tx_hash}/utxos",
            method = "GET",
            headers = API_KEY
        )
    except Exception as e:
        pyscript.write(
            'wait-txs',
            '<h4 style="color: red;">Error when fetching txs from Blockfrost, retry after a minute</h4>'
        )
        spinner = document.querySelector('#spinner')
        spinner.style.display = 'none'
        raise e
    else:
        tx_details = await res1.json()
        slot = tx_details["slot"]
        date = date_from_slot(slot) #UTC
        fees = int(tx_details["fees"])
        utxos = await res2.json()
        utxos = utxos['inputs'] + utxos['outputs']
    
    inputs_sum = 0
    outputs_sum = 0
    for utxo in utxos:
        if utxo['address'] == addr:
            for item in utxo['amount']:
                if item['unit'] == 'lovelace':
                    if "tx_hash" in utxo:
                        # then it's an input
                        inputs_sum += int(item['quantity'])
                    else:
                        # it's an output
                        outputs_sum += int(item['quantity'])
    net_sum = outputs_sum + fees - inputs_sum
    if net_sum == 0:
        tx_type = "Self"
    elif net_sum < 0:
        tx_type = "Send"
        net_sum = round((inputs_sum - outputs_sum)/1e6, 2)
    elif net_sum > 0:
        tx_type = "Receive"
        net_sum = round((net_sum - fees)/1e6, 2)
    
    return (tx_hash, tx_type, net_sum, date)


def date_from_slot(slot: int):
    shelley_unix = 1596491091
    shelley_slot = 4924800
    timestamp = shelley_unix + (slot - shelley_slot)
    return datetime.utcfromtimestamp(timestamp).strftime('%m-%d-%Y %H:%M:%S')

    
async def show_table(data: tuple):
    pyscript.write('table', '')
    df = pd.DataFrame(data, columns=["TxId", "Type", "Amount", "Date (UTC)"])
    table = pn.widgets.Tabulator(pagination='remote', page_size=15)
    table.value = df
    await show(table, 'table')
    table_ele = document.querySelector('#table')
    table_ele.style.position = 'static'
    return df
    

def export_to_csv(df, export_btn):
    export_btn.href = window.URL.createObjectURL(
        Blob.new(
            [df.to_csv()]
        ), 
        { type: "text/plain" }
    )
    export_btn.download = "txhistory.csv"
    

api_key_btn = document.querySelector("#api-key")
api_key_btn.addEventListener('click', create_proxy(add_api_key))
show_tx_btn = document.querySelector("#show-txs")
show_tx_btn.addEventListener('click', create_proxy(fetch_txs))