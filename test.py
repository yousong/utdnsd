#!/usr/bin/env python

import threading
import Queue
import time
import signal
import itertools
# requires dnspython
import dns.exception
import dns.query
import dns.rdatatype

class Result(object):
    def __init__(self, query, ans, elapsed):
        self.query = query
        self.ans = ans
        self.elapsed = elapsed

def summerize(q):
    rs = []
    while not q.empty():
        rs.append(q.get())
    if len(rs) == 0:
        return
    total = len(rs)
    finished = len([r for r in rs if r.ans is not None])
    timeout = total - finished
    total_wait = sum([r.elapsed for r in rs])
    finished_wait = sum([r.elapsed for r in rs if r.ans is not None])
    timeout_wait = total_wait - finished_wait
    avg_wait = total_wait / total
    avg_finished_wait = finished_wait / finished
    summary = (
   '            total: %(total)d\n'
   '         finished: %(finished)d\n'
   '          timeout: %(timeout)d\n'
   '         avg_wait: %(avg_wait).3f\n'
   'avg_finished_wait: %(avg_finished_wait).3f\n'
    )
    summary = summary % {
        'total': total,
        'finished': finished,
        'timeout': timeout,
        'avg_wait': avg_wait,
        'avg_finished_wait': avg_finished_wait,
    }
    print summary


class QueryThread(threading.Thread):
    def __init__(self, q, r, *args, **kwargs):
        super(QueryThread, self).__init__(*args, **kwargs)
        self.q = q
        self.r = r

    def run(self):
        while True:
            try:
                domain = self.q.get(True, 1)
            except Queue.Empty:
                break
            query = dns.message.make_query(domain, dns.rdatatype.A)
            try:
                stime = time.time()
                ans = dns.query.udp(query, '127.0.0.1', timeout=2, port=7001)
                elapsed = time.time() - stime
            except dns.exception.Timeout:
                ans = None
                elapsed = 2
            finally:
                res = Result(query, ans, elapsed)
                self.r.put(res)

class UtdnsdThread(threading.Thread):
    pass

domains = (
    'www.baidu.com',
    'www.twitter.com',
    'www.facebook.com',
    'www.vimeo.com',
    'mail.google.com',
    'www.google.com',
    'www.amazon.com',
    'aws.amazon.com',
    'www.openvpn.net',
)

stop = False
def sighand(signum, frame):
    global stop
    stop = True

if __name__ == '__main__':
    numthreads = 10
    q = Queue.Queue(maxsize=numthreads * 2)
    r = Queue.Queue()
    ts = [QueryThread(q, r) for i in range(numthreads)]
    for t in ts:
        t.start()

    signal.signal(signal.SIGINT, sighand)
    for domain in itertools.cycle(domains):
        if stop:
            break
        q.put(domain)
    for t in ts:
        t.join()
    summerize(r)
