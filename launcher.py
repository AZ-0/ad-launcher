import traceback
import threading
import time
import re

from concurrent.futures import ThreadPoolExecutor
from concurrent import futures
from typing import Any, ByteString
from abc import ABC, abstractmethod

try:
    from tqdm import tqdm # Nice progress bars
except ImportError:
    print("[!] Cannot import tqdm, no progress bar will be displayed even if asked")
    tqdm = lambda x, **_: x

import requests
import brotli
import json

def asbrotli(req):
    def brotlireq(url, data, headers={}, **kwargs) -> requests.Response:
        if 'json' in kwargs:
            data = kwargs.pop('json')
        
        if 'body' in kwargs:
            data = kwargs.pop('body')

        if type(data) in [dict, list, set, tuple]:
            data = json.dumps(data)

        if type(data) is str:
            data = data.encode()

        return req(url, data=brotli.compress(data), headers=headers | { 'Content-Encoding': 'br', 'User-Agent': 'python-requests/2.28.1' }, **kwargs)
    return brotlireq

brotlipost = asbrotli(requests.post)
brotliput  = asbrotli(requests.put)


RESET   = '\x1b[0m'
YELLOW  = '\x1b[33m'
CYAN    = '\x1b[36m'
B_RED   = '\x1b[91m'
B_GREEN = '\x1b[92m'

def flush():
    """Clears ASCII styles and flushes the stdout buffer."""
    print(end=RESET, flush=True)

def log_base(formatter):
    def log(msg: str, log=True, clean=True, **kwargs):
        """Logs a message.

        Parameters:
        - `msg`.        The message to log.
        - `log`.        Whether to actually perform the log.
        - `clean`.      Whether to cleanup ASCII styles and flush the stdout buffer.
        - `kwargs`.     Additional arguments to pass to the underlying `print`.
        """
        if log: print(formatter(msg), **kwargs)
        if clean: flush()

    return log

log_success = log_base(lambda msg: f'{B_GREEN}[+] {msg}{RESET}')
log_info    = log_base(lambda msg: f'{CYAN}[*] {msg}{RESET}')
log_warning = log_base(lambda msg: f'{YELLOW}[!] {msg}{RESET}')
log_error   = log_base(lambda msg: f'{B_RED}[x] {msg}{RESET}')


def make_attack(cmd: str, redirect_err=True):
    """Makes a shell command into an attack usable by the other functions of this module

    Parameters:
    - `cmd`.            A shell command. Should contain `{ip}` parameter, eg. `cmd = "nc {ip} 4096"`.
    - `redirect_err`.   Whether to redirect stderr to stdout and treat it as output. (default True)
    """
    assert '{ip}' in cmd
    import subprocess as sp

    def attack(ip: str) -> bytes:
        p = sp.Popen(
            ['sh', '-c', cmd.format(ip=ip)],
            stdout=sp.PIPE,
            stderr=sp.STDOUT if redirect_err else None
        )

        t = p.stdout.read()
        p.terminate()
        return t

    return attack

class Submitter(ABC):
    @abstractmethod
    def submit(self, flag: str) -> tuple:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

class Launcher(ABC):
    def __init__(self, flag_regex: str, safelist: list, test_id: int = None) -> None:
        '''
        - flag_regex: regex for extracting flags
        - safelist: list of ips not to attack
        - submit_addr: tuple (ip, port) for flag submission
        '''
        self.flag_regex = re.compile(flag_regex)
        self.safelist = safelist
        self.test_id = test_id

    @abstractmethod
    def is_valid(self, flag: str) -> bool:
        ...

    @abstractmethod
    def get_submitter(self) -> Submitter:
        ...

    @abstractmethod
    def get_team_ids(self) -> list:
        ...
    
    @abstractmethod
    def id_to_ip(self, id: str) -> str:
        ...


    def normalize_flags(self, flags: Any) -> list:
        """Normalizes raw data into flags.
        Bytelike objects will be decoded to strings, strings will be stripped, and a sequence will be turned into a list.
        
        Returns a list containing the normalized flags.

        Examples: (assuming the flag regex is `flag{[a-zA-Z0-9_!]+}`)
        ```py
        normalize_flags(bytearray(b'  flag{ayayay} ')) -> ['flag{ayayay}']
        normalize_flags({ b'  flag{ayayay}  a..rd.lk flag{4m4z1ng_f!4g} wxUcb flag{?}' }) -> ['flag{ayayay}', 'flag{4m4z1ng_f!4g}']
        ```
        """
        if isinstance(flags, (str, ByteString)):
            flags = [flags]

        try:
            flags = list(flags)
        except TypeError:
            log_warning(f"Unable to normalize '{flag}' as a sequence of flags.")
            return

        normalized = []
        for flag in flags:
            if isinstance(flag, ByteString):
                try:
                    flag = str(flag, encoding='utf8')
                except UnicodeDecodeError:
                    flag = str(flag, encoding='latin1')
            try:
                extracted = self.flag_regex.findall(flag)
                normalized.extend(extracted)
            except:
                log_warning(f"Unable to extract flags from '{flag}'.")

        return normalized


    def filter_valids(self, flags: list, *args) -> tuple:
        """Given a list of flags, returns those that are valid and the reasons the rest aren't."""
        reasons = set()
        valids = []

        for flag in flags:
            valid, reason = self.is_valid(flag, *args)
            if valid:
                valids.append(flag)
            else:
                reasons.add(reason)

        return valids, reasons


    def submit_flags(self, flags: list[str], log=True, progress_bar=True) -> None:
        """Submits the given flags to the remote.

        Parameters:
        - `flags`.  The flags to submit.
        - `log`.    Whether to log the submission statuses.
        """
        if not flags:
            log_warning("No flags to submit", log=log)
            return

        log_info(f"Submitting {len(flags)} flags", log=log)

        s = self.get_submitter()
        submitted = []

        for flag in tqdm(flags, disable=not progress_bar):
            success, msg = s.submit(flag)
            if success:
                log_success(msg, log=log)
                submitted.append(flag)
            elif 'INV' in msg:
                log_error(msg, log=log)
            else:
                log_warning(msg, log=log)

        s.close()
        return submitted


    def test_attack(self, attack) -> list:
        """Performs a test run for an attack.

        Parameters:
        - `attack`.     The attack to run. A callable that accepts an ip and attack info, and returns one or several flags, as str, bytelike, or a sequence thereof.
        """
        if self.test_id is None:
            log_error('No testing ip provided, unable to test attack')
            return

        log_info(f"Testing attack {attack} on at test team {self.test_id}.")

        raw = attack(self, self.test_id, self.id_to_ip(self.test_id))
        log_success("Raw output of attack:")
        print("="*50, raw, "="*50, sep='\n')

        flags = self.normalize_flags(raw)
        if not isinstance(flags, list):
            log_warning(f"Couldn't normalize alleged flags '{raw}': make sure it's an str, bytelike, or sequence thereof.")
            return

        if flags:
            log_success(f"Recovered flags: {flags}")
        else:
            log_error("Couldn't recover any flags")

        valids, reasons = self.filter_valids(flags)

        if valids:
            log_success(f"Valid flags: {valids}")
        else:
            log_error(f"No valid flags: {reasons}")

        return valids


    def run_attack(self, attack, team: str, submit=True, log=True, progress_bar=True) -> list:
        """Runs an attack targeting a specific team.

        Parameters:
        - `attack`.       The attack to run. A callable that accepts an ip and attack info, and returns one or several flags, as str, bytelike, or a sequence thereof.
        - `team`.         The team to attack.
        - `submit`.       Whether to submit recovered flags (default True).
        - `log`.          Whether to log amount of valids flags and submission info (default True). Normalization errors will be logged anyways!
        - `progress_bar`. Whether to display a progress bar upon flag submission (default True).
        """
        # [---------- TODO: Implement finer control over logging ----------]
        try:
            flags = self.normalize_flags(attack(self, team, self.id_to_ip(team)))
        except KeyboardInterrupt:
            log_warning(f"User interrupted the attack on team {team}")
            raise
        except:
            log_error(f"An exception occured while attacking team {team}")
            traceback.print_exc()
            return [], []

        valids, reasons = self.filter_valids(flags)

        if not valids or flags is None:
            log_error(f"Team {team} has invalid flags '{flags}': {reasons}")
            return [], []

        log_success(f"Found {len(valids)} valid flags", log=log)
        if submit:
            return valids, self.submit_flags(valids, log=log, progress_bar=progress_bar)

        return valids, []


    def broadcast_attack(self, attack, submit=True, threads=None, submit_batch=False, progress_bar=False) -> dict:
        """Broadcasts an attack over all teams.

        Parameters:
        - `attack`.         The attack to run. A callable that accepts an ip and returns one or several flags, as str, bytelike, or a sequence thereof.
        - `threads`.        The amount of threads (default None). If None, doesn't parallelize.
        - `submit_batch`.   Whether to submit flag in batches
        - `progress_bar`.   Whether to display a progress bar (default False). Only for non-parallelized mode. Disables attack run logs.
        """
        # [---------- TODO: Refresh not only on startup ----------]
        # Exploits taking long enough to run might use outdated data.
        # Launch a thread that refreshes automatically twice per tick?

        # [---------- TODO: Less fragile progress bar ----------]
        # Use pwntools logging module?

        results = {}
        kwargs = { 'submit': submit and not submit_batch, 'log': not progress_bar, 'progress_bar': False }
        start = time.time()

        if submit_batch:
            batch = []

        ips = self.get_team_ids()
        if not threads:
            for team in tqdm(ips, disable=not progress_bar):
                if team in self.safelist:
                    continue

                try:
                    flags = self.run_attack(attack, team, **kwargs)
                    results[team] = len(flags[0]), len(flags[1])
                    if submit_batch:
                        batch.extend(flags)

                except KeyboardInterrupt:
                    if input("Do you wish to continue the broadcast? [y/n]: ")[0].lower() == 'n':
                        raise
                    log_info(f"Resuming broadcast (interrupted at team {team})")

        else:
            with ThreadPoolExecutor(threads, 'broadcast') as executor:
                runs = {}

                for team in tqdm(ips, 'loading'):
                    if team in self.safelist:
                        continue
                    runs[executor.submit(self.run_attack, attack, team, **kwargs)] = team

                for future in tqdm(futures.as_completed(runs.keys()), total=len(runs), disable=not progress_bar):
                    team  = runs[future]
                    flags = future.result()
                    results[team] = len(flags[0]), len(flags[1])
                    if submit_batch:
                        batch.extend(flags)

        # Statistics
        attacked    = sum(bool(r[0]) for r in results.values())
        flag_amount = sum(r[0] for r in results.values())

        if submit and submit_batch:
            ok = self.submit_flags(batch, log=not progress_bar, progress_bar=False)
            ok_amount = len(ok)
        else:
            ok_amount = sum(r[1] for r in results.values())

        log_success(f'Broadcast completed! This took {time.time() - start} seconds, with {threads} threads.')
        log_success(f'Found {YELLOW}{flag_amount} {B_GREEN}flags total. Submitted {YELLOW}{ok_amount} {B_GREEN}new ones.')
        log_success(f'Successfully attacked {YELLOW}{attacked}{B_GREEN}/{YELLOW}{len(results)}{B_GREEN} teams')
        return results


    def loop_attack(self, attack, delay=0, **kwargs) -> list:
        """Broadcasts an attack in an infinite loop (will stop cleanly upon KeyboardInterrupt).

        Parameters:
        - `attack`.     The attack to run. A callable that accepts an ip and returns one or several flags, as str, bytelike, or a sequence thereof.
        - `delay`.      The delay between loops, in seconds (default 0).
        - `kwargs`.     Additional parameters to pass to `broadcast_attack`.
        """
        if delay:
            ticker = threading.Event()

        results = []

        try:
            once = True
            while once or not delay or not ticker.wait(delay):
                once = False # We don't want to wait for the delay the first time

                try:
                    log_info("#"*100)
                    log_info(f"NEW LOOP: Broadcasting attack {attack}")
                    results.append(self.broadcast_attack(attack, **kwargs))

                except KeyboardInterrupt:
                    if input("Do you wish to continue the broadcasting loop? [y/n]: ")[0].lower() == 'n':
                        raise
                    log_info(f"Running another broadcast")

                except:
                    log_error(f"An exception occured during broadcast of {attack}")
                    traceback.print_exc()

        except KeyboardInterrupt:
            log_info("#"*22)
            log_info("Exiting attack loop...")
            log_info("#"*22)

        return results