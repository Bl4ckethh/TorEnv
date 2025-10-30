#!/usr/bin/env python3
from torenv import TorSession
import time, random

tor = TorSession()
tor.setup_multi_instance(5, rotate=True)

for i in range(10):
    resp = tor.make_request(f"https://httpbin.org/ip?{i}")
    if resp:
        print(f"[{tor.current_idx}] IP: {resp.json()['origin']}")
    time.sleep(random.uniform(1, 3))
