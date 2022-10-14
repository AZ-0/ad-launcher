import traceback
import threading
import time
import re

from concurrent.futures import ThreadPoolExecutor
from concurrent import futures
from typing import Any
from enum import Enum
from abc import ABC, abstractmethod

import requests
import brotli
import json


########################################## LOGGING ##########################################


COLOR_RESET = '\x1b[0m'
YELLOW  = '\x1b[33m'
CYAN    = '\x1b[36m'
B_RED   = '\x1b[91m'
B_GREEN = '\x1b[92m'

def log_base(formatter):
    def log(msg: str, log=True, flush=True, **kwargs):
        """Logs a message.

        Parameters:
        - `msg`.        The message to log.
        - `log`.        If false, doesn't print anything.
        - `flush`.      Whether to flush stdout (default True).
        - `kwargs`.     Additional arguments to pass to the underlying `print`.
        """
        if log: print(formatter(msg), flush=flush, **kwargs)

    return log

log_success = log_base(lambda msg: f'{B_GREEN}[+] {msg}{COLOR_RESET}')
log_info    = log_base(lambda msg: f'{CYAN}[*] {msg}{COLOR_RESET}')
log_warning = log_base(lambda msg: f'{YELLOW}[!] {msg}{COLOR_RESET}')
log_error   = log_base(lambda msg: f'{B_RED}[x] {msg}{COLOR_RESET}')


########################################## SUBMITTER ##########################################


class FlagStatus(Enum):
    OK  = 0  # The flag is valid
    INV = 1  # The flag is invalid (bad format / fake flag)
    OLD = 2  # The flag was issued too many ticks ago
    DUP = 3  # The flag was already submitted
    ERR = 4  # The server encountered an error
    UNK = 5  # What the hell is going on?

    @classmethod
    def from_str(cls, raw: str):
        return cls.__members__.get(raw, cls.UNK)


class Submitter(ABC):
    @abstractmethod
    def submit(self, flag: str) -> tuple:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, typ, err, tb):
        if err is not None:
            log_error(f"An unexpected error occured during flag submission: {err}")
            traceback.print_exception(typ, err, tb)

        self.close()
        return True # suppress the exception


########################################## LAUNCHER ##########################################


class Launcher(ABC):
    def __init__(self, flag_regex: str, safelist: list, test_id: int = None) -> None:
        """
        - `flag_regex`. Regex for extracting flags.
        - `safelist`.   List of ips not to attack — usually, you and the NOP team.
        - `test_id`.    The id of the team on which to test your attacks — usually, the NOP team).
        """
        self.flag_regex = re.compile(flag_regex)
        self.safelist = safelist
        self.test_id = test_id
        self.flag_cache = set()


    @abstractmethod
    def is_valid(self, flag: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_team_ids(self) -> list:
        raise NotImplementedError
    
    @abstractmethod
    def id_to_ip(self, id: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_submitter(self) -> Submitter:
        raise NotImplementedError


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
        normalized = []
        
        try:
            extracted = self.flag_regex.findall(str(flags))
            normalized.extend(extracted)
        except:
            log_warning(f"Unable to extract flags from '{flags}'.")

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


    def submit_flags(self, flags: list[str], log=True) -> int:
        """Submits the given flags to the remote.

        Parameters:
        - `flags`.  The flags to submit.
        - `log`.    Whether to log the submission statuses.
        """
        if not flags:
            log_warning("No flags to submit", log=log)
            return

        new = [flag for flag in flags in flag not in self.flag_cache]
        log_info(f"Submitting {YELLOW}{len(new)} {CYAN}new flags ({YELLOW}{len(flags) - len(new)} {CYAN}were cached)", log=log)

        valids = 0
        with self.get_submitter() as s:
            for flag in new:
                status, msg = s.submit(flag)
                self.flag_cache.add(flag)

                if status == FlagStatus.OK:
                    log_success(msg, log=log)
                    valids += 1

                elif status in (FlagStatus.OLD, FlagStatus.DUP):
                    log_warning(msg, log=log)

                else:
                    log_error(msg, log=log)
                    if status != FlagStatus.INV:
                        self.flag_cache.remove(flag)

        return valids


    def test_attack(self, attack) -> list:
        """Performs a test run for an attack.

        Parameters:
        - `attack`.     The attack to run.
        """
        if self.test_id is None:
            log_error('No testing ip provided, unable to test attack')
            return []

        log_info(f"Testing attack {attack} on test team {self.test_id}.")

        raw = attack(self, self.test_id, self.id_to_ip(self.test_id))
        log_success("Raw output of attack:")
        print("="*64, raw, "="*64, sep='\n')

        flags = self.normalize_flags(raw)
        if not isinstance(flags, list):
            log_warning(f"Couldn't normalize alleged flags from raw output: make sure it's an str, bytelike, or sequence thereof.")
            return []

        log_success(f"Recovered flags: {flags}") if flags else log_error("Couldn't recover any flags")
        valids, reasons = self.filter_valids(flags)

        log_success(f"Valid flags: {valids}") if valids else log_error(f"No valid flags: {reasons}")
        return valids


    def run_attack(self, attack, team: str, submit=True, log=True) -> tuple:
        """Runs an attack targeting a specific team.

        Parameters:
        - `attack`.       The attack to run. A callable that accepts an ip and attack info, and returns one or several flags, as str, bytelike, or a sequence thereof.
        - `team`.         The team to attack.
        - `submit`.       Whether to submit recovered flags (default True).
        - `log`.          Whether to log amount of valids flags and submission info (default True). Normalization errors will be logged anyways!
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
            return [], 0

        flags, reasons = self.filter_valids(flags)

        if not flags:
            log_error(f"Team {team} has invalid flags '{flags}': {reasons}")
            return [], 0

        log_success(f"Found {len(flags)} valid flags", log=log)
        if submit:
            return flags, self.submit_flags(flags, log=log)

        return flags, 0


    def broadcast_attack(self, attack, threads=0, submit=True, submit_batch=False, **kwargs) -> dict:
        """Broadcasts an attack over all teams.

        Parameters:
        - `attack`.         The attack to run. A callable that accepts an ip and returns one or several flags, as str, bytelike, or a sequence thereof.
        - `threads`.        The amount of threads (default 0). If 0, doesn't parallelize.
        - `submit_batch`.   Whether to submit flag in batches
        - `kwargs`.         Additional keyword arguments to pass to `run_attack` 
        """

        results = {}
        kwargs |= { 'submit': submit and not submit_batch }
        start = time.time()

        ids = [team for team in self.get_team_ids() if team not in self.safelist]
        if not threads:
            for team in ids:
                try:
                    flags, valids = self.run_attack(attack, team, **kwargs)
                    results[team] = flags, valids

                except KeyboardInterrupt:
                    if input("Do you wish to continue the broadcast? [y/n]: ").zfill(1)[0].lower() != 'y':
                        raise
                    log_info(f"Resuming broadcast (interrupted at team {team})")

        else:
            with ThreadPoolExecutor(threads, 'broadcast') as executor:
                runs = {}

                for team in ids:
                    future = executor.submit(self.run_attack, attack, team, **kwargs)
                    runs[future] = team

                for future in futures.as_completed(runs.keys()):
                    team  = runs[future]
                    flags, valids = future.result()
                    results[team] = flags, valids

        batch = [flag for flags, _ in results.values() for flag in flags]
        if submit and submit_batch:
            valids = self.submit_flags(batch, log=True)
        else:
            valids = sum(r[1] for r in results.values())

        # Statistics
        attacked = sum(bool(r[0]) for r in results.values())

        log_success(f'Broadcast completed! This took {YELLOW}{time.time() - start} {B_GREEN}seconds, with {YELLOW}{threads} {B_GREEN}threads.')
        log_success(f'Found {YELLOW}{len(batch)} {B_GREEN}flags total. Submitted {YELLOW}{valids} {B_GREEN}valid ones.')
        if not submit:
            log_warning('Flag submission was disabled')
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
                    if input("Do you wish to continue the broadcasting loop? [y/n]: ").zfill(1)[0].lower() != 'y':
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


########################################## MISC ##########################################


def make_attack(cmd: str, redirect_err=True, timeout=None):
    """Makes a shell command into an attack usable by the other functions of this module

    Parameters:
    - `cmd`.            A shell command. Should contain `{ip}` parameter, eg. `cmd = "nc {ip} 4096"`.
    - `redirect_err`.   Whether to redirect stderr to stdout and treat it as output. (default True)
    """
    assert '{id}' in cmd and '{ip}' in cmd # if you don't use the args, put them behind a comment
    import subprocess as sp

    def attack(ctx, id, ip: str) -> bytes:
        p = sp.Popen(
            ['bash', '-c', cmd.format(id=id, ip=ip)],
            stdout=sp.PIPE,
            stderr=sp.STDOUT if redirect_err else sp.PIPE
        )

        try:
            p.wait(timeout)
        except sp.TimeoutExpired:
            p.terminate()

        return p.stdout.read()

    return attack


def asbrotli(req):
    def brotlireq(url, data={}, headers={}, **kwargs) -> requests.Response:
        if 'json' in kwargs:
            data = kwargs.pop('json')

        if 'body' in kwargs:
            data = kwargs.pop('body')

        if isinstance(data, (dict, list, set, tuple)):
            data = json.dumps(data)

        if isinstance(data, str):
            data = data.encode()

        return req(url, data=brotli.compress(data), headers=headers | { 'Content-Encoding': 'br' }, **kwargs)
    return brotlireq

brotlipost = asbrotli(requests.post)
brotliput  = asbrotli(requests.put)
