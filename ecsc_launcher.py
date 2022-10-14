from launcher import Submitter, Launcher
from requests import get
from random import shuffle
from time import time
from pwn import remote, context


INFO_ENDPOINT = 'http://10.10.254.254/competition/teams.json'
TEAM_FR = 10

class ECSCSubmitter(Submitter):
    def __init__(self) -> None:
        self.old_level = context.log_level
        context.log_level = 'error'

        self.io = remote('10.10.254.254', 31337)
        self.io.recvline()
        self.io.recvline()
        self.io.recvline()

    def submit(self, flag: str) -> tuple[bool, str]:
        self.io.sendline(flag)
        res = self.io.recvline(False)
        return b'OK' in res, res.decode()

    def close(self):
        self.io.close()
        context.log_level = self.old_level

class ECSCLauncher(Launcher):
    def __init__(self) -> None:
        super().__init__(flag_regex=r'ECSC_[A-Za-z0-9\+/]{32}', safelist=[1, TEAM_FR], test_id=1)
        self.last_refresh = 0

    def refresh(self):
        now = time()

        if now - self.last_refresh > 3: # refresh every 3 seconds
            raw = get(INFO_ENDPOINT).json()
            self.teams = raw['teams']
            self.flag_ids = raw['flag_ids']
            self.last_refresh = now

    def get_flag_ids(self) -> dict:
        self.refresh()
        return self.flag_ids

    ### Implementation of abstract methods

    def is_valid(self, flag: str) -> bool:
        return bool(self.flag_regex.match(flag)), 'bad flag format'

    def get_submitter(self) -> ECSCSubmitter:
        return ECSCSubmitter()

    def get_team_ids(self) -> list:
        self.refresh()
        shuffle(self.teams) # Don't attack the same teams in the same order accross broadcasts
        return self.teams

    def id_to_ip(self, id: str) -> str:
        return f'10.10.{id}.1'