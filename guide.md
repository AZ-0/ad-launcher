<p><center><h1>The most complete guide to the awesome launcher</h1>
By yours truly, A~Z</center></p>

## Table of contents


## Instantiating the launcher

The `launcher.py` file contains a generic base that can be reused accross most A/D CTF.
To use it in a specific one, you will need to instantiate two abstract classes, `Launcher` and `Submitter`.

### Launcher

```py
class ECSCLauncher(Launcher):
    def __init__(self) -> None:
        super().__init__(flag_regex=r'ECSC_[A-Za-z0-9\+/]{32}', safelist=[1, TEAM_FR], test_id=1)
        self.last_refresh = 0

    def refresh(self):
        #
        # If you don't need flag ids, comment the if statement and everything in it
        # If you still needs the team list (and they are constant, which they probably should), set it with `self.teams = [...]`
        #        
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
        # if you run the process two times in a row, don't lose time attacking the same teams
        shuffle(self.teams)
        return self.teams

    def id_to_ip(self, id: int) -> str:
        return f'10.10.{id}.1'
```

The `Launcher` class specifies 4 abstract methods and a few args at initialisation.

- `self.is_valid(flag: str) -> tuple[bool, str]`. check whether a flag is valid, and if not returns the reason it isn't.
Usually this will be a simple regex match, but sometimes you can verify a flag before submission using extra information given by the admins.

- `self.get_team_ids() -> list[str|int]`. returns the list of all teams, by id.

- `self.id_to_ip(id: str|int) -> str`. gets the ip of the team associated to the given id.

- `self.get_submitter() -> Submitter`. instanciates a submitter; see below.

- `self.__init__(flag_regex: str, safelist: list[int|str], test_id: int|str = None)`
    1. `flag_regex` is a regex matching flags; if there is no known format, give `.+`. This will be used to extract flags from attacks outputs.
    2. `safelist` is a list containing the ids of the teams not to attack.
    That's usually you and the NOP team, but might also include top competitors if you don't want them stealing exploits.
    3. `test_id` is the id of the NOP team.
    If such a team doesn't exist, don't specify it upon instanciation.




### Submitter

```py
class ECSCSubmitter(Submitter):
    def __init__(self) -> None:
        self.old_level = context.log_level
        context.log_level = 'error'

        self.io = remote('10.10.254.254', 31337)
        self.io.recvline()
        self.io.recvline()
        self.io.recvline()

    def submit(self, flag: str) -> tuple[FlagStatus, str]:
        self.io.sendline(flag)
        res = self.io.recvline(False).decode()
        return FlagStatus.from_str(res.split(' ')[1]), res

    def close(self):
        self.io.close()
        context.log_level = self.old_level
```

The submitter is what submits your flags (wow, isn't that obvious).
In this case it's a class inheriting `Submitter`, implementing two abstract methods: `submit` and `close`.

`submit` is the most important, giving your flag to the remote and returning the status (OK, INV, OLD, DUP, ERR, UNK. see the comments on `FlagStatus`'s source for more precisions) as well as the message from the remote.

`close` will be called at the end of the launcher's `submit_flag` method, to close eventual pending connections to the remote.


## Running an attack

```py
from ecsc_launcher import ECSCLauncher
from launcher import brotlipost, log_warning
import requests, json

def attack(ctx, id, ip):
    bot_names = ctx.get_flag_ids()['dummy-web_flagstore1'][str(id)]
    flags = []
    for bot_name in bot_names:
        try:
            flags.append(brotlipost(f"http://{ip}:10021/flagstore1", data={'username':bot_name}, timeout=2).json()['secret'])
        except requests.exceptions.ReadTimeout:
            log_warning("Timed out!")

    return flags

attack.__qualname__ = 'dummy-web_flagstore1'

launcher = ECSCLauncher()
launcher.loop_attack(attack, delay=2)
```

### The attack function

In this launcher, attack functions come in a special format: they accept three arguments `ctx` (the launcher itself), `id` (the id of the team being attacked), and `ip` (the ip of the same team).
They return the stolen flags, possibly in an extremely dirty format. as long as it's bytes or string, the launcher will use the flag regex to extract 'em flags.

If your attack has a chance of hanging (eg. if the attacked service implements mitigations and you wait forever for something that doesn't come), you should implement a timeout.
Otherwise, attacking one team might stop the whole launcher: at this point you can only drop the attack on that team manually by `^C`-ing (this will stop cleanly, asking you whether you want to continue the broadcast).

### Running

To run the attack against a specific team, use
```py
def run_attack(self, attack, team: str, submit=True, log=True) -> tuple[list[str], int]
```
The parameters are as follow:
- `attack`. the attack function.
- `team`. the id of the team to target.
- `submit`. whether to submit the recovered flags to the remote.
- `log`. whether to log amount of valids flags and submission info.

This returns the list of recovered flags and the amount of valid ones (`0` if `submit` was `False`).


### Broadcasting

A broadcast will run the attack across all teams, possibly threaded.
```py
launcher.broadcast_attack(attack, threads=0, submit=True, submit_batch=False, **kwargs) -> dict[str|int, tuple[list[str], int]]:
```
The parameters are as follow:
- `attack`. the attack function.
- `threads`. the amount of threads to use. If it is `0` or `None`, doesn't parallelize the broadcast.
- `submit`. whether to submit the recovered flags
- `submit_batch`. only works if `submit` is `True`. Whether to submit the flags in batch after the broadcast.
-  `kwargs`. additional keyword arguments to pass to `run_attack`.

This returns a dictionary of the form `results[team_id] = run_attack(...)`, ie to each team id is associated the recovered flags and the amount of valid ones (`0` if `submit` was `False` or `submit_batch` was `True`).

Batch submission is useful if you need to reduce the amount of connections to the submission remote; the default behaviour of the launcher is to connect after each and every attack and submit the flags then.
Enabling the batch will store the flags and submit them all after a broadcast, in a single connection.
This can be dangerous: if the broadcast takes too long, the first collected flag might become irrelevant by the end. If the remote is unstable, the connection getting killed will drop all the not yet submitted flags.

If the launcher hangs during a broadcast, you can keyboard interrupt it.
It will stop cleanly, asking whether you want to resume broadcating at the next team (interrupting it once again as that point counts as no).
In threaded mode, resuming is impossible so it will stop the broadcast entirely without asking.


### Looping

A loop is basically infinite broadcasts, run back-to-back.
```py
launcher.loop_attack(attack, delay=0, **kwargs) -> list[dict[str|int, tuple[list[str], int]]]:
```
The parameters are as follow:
- `attack`. the attack function.
- `delay`. the time to sleep for between broadcasts.
- `kwargs`. additional arguments to pass to `broadcast_attack`

This returns a list containing the results of each broadcast.

The `delay` is there to prevent your exploit from being dos-protection-ed in the case it runs very fast.
If a tick lasts 3 minutes, it is ideal for the broadcast to run every 2 minutes (roughly): you can increase the threading to bring it around there if it is slow, and you can increase the delay to bring it around there if it is fast.
You should probably never have both high delay and high threading.


### Testing

```py
launcher.test_attack(attack) -> list[str]
```
This returns the extracted valid-looking flags.

This is basically a `run_attack` against the NOP team (if specified at initialisation of the launcher) with more logs than usual.
You probably want to use this method instead of live testing against other teams.

You can also use it to run the attack against yourself and check whether you are safe.
```py
# If you just test against prod
launcher.test_id = your_id
# If you've got a staging environment different from prod
launcher.id_to_ip = lambda *: 'ip to the staging environment'

launcher.test_attack(attack)
```


## Running a non-standard attack

For whatever reason, an attack might not fit the usual mold of connecting to the service, attacking it, then returning the flags.
Worry not! When this happens, you can still run the attack nicely thanks to the primitives of the launcher.

### Extracting flags

When you've got some output, don't bother parsing it: just apply this function that will extract everything that looks like a flag.
```py
launcher.normalize_flags(flags: Any) -> list[str]:
```
Usually, it's best to use it as `launcher.normalize_flags(str(output))`, where `output` is the completely raw output of your attack.


### Submitting flags

```py
launcher.submit_flags(flags: list[str], log=True) -> int:
```
The parameters are as follow:
- `flags`. the flags to submit.
- `log`. whether to log submission info.

This returns the amount of actually valid flags.

This method automatically handles flag caching: it won't submit any flag that it has already submitted, except if the status was ERR or UNK.

### Non-python attacks

Sometimes, an attack might be much easier to implement in a language other than python.
However, this isn't a problem for the launcher!
```py
from launcher import make_attack
from ecsc_launcher import ECSCLauncher

attack = make_attack('./my_exploit {id} {ip}', timeout=10)
ECSCLauncher().test_attack(attack)
```

```py
make_attack(cmd: str, redirect_err: bool=True, timeout: float=None) -> Callable[[Launcher, str|int, str], bytes]
```
The arguments are as follow:
- `cmd`. the shell command to run.
- `redirect_err`. whether to redirect stderr to stdout to also extract flags from there.
- `timeout`. the maximum time in seconds for which the exploit is allowed to run before getting terminated. The default is waiting forever.

This returns an attack function usable by the other primitives of the launcher.


## Tips

### Logging

There are some "logging" (read: fancy prints) functions.
```py
log_success("at last") → '[+] at last'      # printed in green
log_info("am working") → '[*] am working')  # printed in blue
log_warning("pls no!") → '[!] pls no!')     # printed in yellow
log_error("ERROOORRR") → '[x] ERROOORRR')   # printed in red
```
Use 'em if you wanna have fancy colored output.
These functions flush stdout by default, you can disable it with `flush=False`.
Additional keyword arguments are passed to the underlying print.

### Escaping traffic monitoring

There are several ways to trip up people monitoring your traffic and stealing your exploits.
A simple one is to brotli compress your http requests, making it a pain to take a good look at them.
As a nice side effect, this might also cause bugs in tools such as Flower — to be confirmed.

There are two methods, `brotlipost` and `brotliput`, that do exactly that; use them as you would `requests`' post and put methods.
If you need a more esoteric method, you can use it with eg. `as_brotli(requests.option)` — it's untested and not guaranteed to work, look at the source code and fit it to your needs.

### Clearing cache

Submitting flags through `launcher.submit_flags` automatically caches them in `launcher.flag_cache`.
This cache is never cleared.
While I don't think this should be too much of a problem, you might want to clear the cache every half an hour or so to avoid storing thousands of flags for nothing.
You just have to call `launcher.flag_cache.clear()`.

### When you don't have ids

It might happen that there are no team ids to work with, everything being raw ips to use on the network.
This is not a problem; treat every ip as the team id and define `id_to_ip` as below:
```py
def id_to_ip(self, id: str) -> str:
    return id
```