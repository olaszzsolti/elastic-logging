#!/usr/bin/python3

import argparse
import copy
import datetime
import json
import os
import pytz
import random
import string
import threading
import time
import requests
import numpy as np

PROCESSORS = {"elastic": ['unprocessed', 'filebeat',
                          'logstash', 'elasticsearch'],
              "fluent": ['unprocessed', 'fluentbit',
                         'logstash', 'elasticsearch']}
DEFAULT_PROCESSOR = PROCESSORS[list(PROCESSORS.keys())[0]][0]
DEFAULT_STACK = list(PROCESSORS.keys())[0]
DEFAULT_PERIOD = 5.0
DEFAULT_COUNT = 1
DEFAULT_MSG_COUNT = 1
DEFAULT_MSG_LEN = 3
DEFAULT_LOG_FORMAT = "json"
DEFAULT_FINISH_AFTER_SEC = False
DEFAULT_SIZE = 64000


LOG_TEMPLATE = {"version": "0.2.0",
                "timestamp": None,
		"severity": None,
		"service_id": None,
                "message": None}

SEVERITIES = ["critical", "error", "warning", "info", "debug"]
MESSAGES = {}
LETTERS = string.ascii_lowercase + " "

# Specify which files to use for the specific log.
FILES = {"HangingResources": "HangingResources.log", "Big": "Big.log"}
# Possible domains.
TLDS = ["ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao",
        "aq", "ar", "as", "at", "au", "aw", "ax", "az", "ba", "bb",
        "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo",
        "bq", "br", "bs", "bt", "bw", "by", "bz", "ca", "cc", "cd",
        "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "com",
        "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk",
        "dm", "do", "dz", "ec", "edu", "ee", "eg", "eh", "er", "es",
        "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gd",
        "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq",
        "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr",
        "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir",
        "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki",
        "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc",
        "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc",
        "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp",
        "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
        "na", "nc", "ne", "net", "nf", "ng", "ni", "nl", "no", "np",
        "nr", "nu", "nz", "om", "org", "pa", "pe", "pf", "pg", "ph",
        "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa",
        "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se",
        "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss",
        "st", "su", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg",
        "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv",
        "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc",
        "ve", "vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt", "za",
        "zm", "zw"]

def timestamp(simple_time_offset=False) -> str:
    """Create a timestamp according to sample logs.

    Follows this format: 2019-01-30T11:24:15.518+0100
    """
    ts = pytz.utc.localize(
        datetime.datetime.utcnow()).isoformat(timespec='milliseconds')
    if simple_time_offset:
        return f"{ts[:-3]}{ts[-2:]}"
    else:
        return ts


def random_ip_addr() -> str:
    """Generate a random IPv4 address.
    """
    return ".".join([str(random.randint(1, 254)) for _ in range(0, 4)])


def random_domain_name() -> str:
    """Generate a random domain name.
    """
    case = random.choice(["lower", "upper"])
    parts = []
    # Create a domain having at least 1 and at most 5 sub parts.
    for _ in range(random.randint(1, 5)):
        # Create a sub part having a length of at most 8 characters.
        parts.append(''.join(random.choice(getattr(string, f"ascii_{case}case")) for __ in range(random.randint(1, 8))))
        
    top_level = random.choice(TLDS)
    if case == "upper":
        top_level = top_level.upper()
    parts.append(top_level)

    return ".".join(parts)

    
def random_sip_id() -> str:
    """Create a random SIP ID.
 
    The ID follows this format: sip:<~phone number>@<domain name or IP
    address><user type>. User type can be `phone` or left
    unspecified. All fields are filled with random values.

    """
    domain_name = random.choice([True, False])
    if domain_name:
        domain_name = random_domain_name()
    else:
        domain_name = random_ip_addr()
    return f"sip:{random.choice(['+', ''])}{random.randint(1, 99999999999)}@{domain_name}{random.choice([';user=phone', ''])}"


def random_sip_call_id() -> str:
    """Create random SIP call ID.
    
    Create a 32 characters log random alphanumbic values. (Tries to mimic those show among the samples).
    """
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))
        
            
def create_HangingResources_log(log_format, size) -> str:
    """Create a Hanging Resources type log.

      Generated log follows the structure of these samples:
    - Log sample 1:
      2019-01-30T11:24:15.518+0100 PayloadMatedPair=2 \u200bsip:+34856589407@ICSCF111.IMS.MNC004.MCC214.3GPPNETWORK.ORG;user=phone,sip:+34856116240@10.14.44.69;user=phone,p65540t1548843697m526322c61332s2,1007682,ip/42/2/1015363,media_inactivity\u200b
      Here the comma separated fields have the following keys in
      order: callee, caller, call_id, context_id, termination_id,
      unnamed (this is referred to as message or reason for now).

    - Log sample 2:
      2019-01-30T13:03:01.553+0100 PayloadMatedPair=1 6805,ip/69/2/13610,normal_oab_process
      Here the comma separated fields have the following keys in
       order: `context_id`, `termination_id`, `message/reason`.

    Provided log samples are always padded to 571 characters with
    spaces. They showed two kinds of message/reason part:
    `media_inactivity\u200b` or `normal_oab_process` the first having always
    6 comma separated values (see sample 1) while the second only 3
    (see sample 2). The `PayloadMatedPair` field showed values in the
    range of 1--3.

    """
    log_data = {"timestamp": timestamp(simple_time_offset=True),
                "PayloadMatedPair": str(random.randint(1, 3)),
                "message": random.choice(["media_inactivity", "normal_oab_process"]),
                # termination_id follows this format:
                # ip/<number>/<number>/<number>. Size of numbers tries
                # to approach the ones seen among the samples.
                "termination_id": f"ip/{random.randint(0, 999)}/{random.randint(0, 999)}/{random.randint(0, 10000000)}",
                # context_id seems to a random number in the samples.
                "context_id": str(random.randint(0, 10000000))}

    if log_data["message"] == "media_inactivity\u200b":
        log_data["callee"] = random_sip_id()
        log_data["caller"] = random_sip_id()
        log_data["call_id"] = random_sip_call_id()

    log_format = log_format.lower()
    if log_format == "json":
        # Create a JSON including the specified field names as
        # well. Skip padding.
        return json.dumps(log_data)
    elif log_format == "plain":
        # Create a string without specifying field names, same as in
        # log samples.
        rest = [log_data.get(key) for key in ["callee", "caller", "call_id", "context_id", "termination_id", "message"]]
        rest = [i for i in rest if i != None]
        log_data = f'{log_data.pop("timestamp")} PayloadMatedPair={log_data.pop("PayloadMatedPair")} {",".join(rest)}'
        # Add padding to 571 characters.
        padding = 571 - len(log_data)
        if padding > 0:
            log_data = f"{log_data}{' ' * padding}"
        return log_data
        
def get_record_sizes(exp_lambda, count, limit_min=10000, limit_max=64535):
    """" Create random record sizes of (more or less) exponential distribution.

EXP_LAMBDA: lambda parameter of the exponential distribution.
COUNT: create this many random numbers.
LIMIT_MIN: the minimum for any random value generated.
LIMIT_MAX: the maximum for any random value generated.
"""
    vals = (np.random.exponential(1/exp_lambda, count) * limit_max) + limit_min
    return [int(v) if v < limit_max else int(limit_max) for v in vals]

def send_log():

    exp_lambda = 17 # ~1 64k sized in every 100k records
    # exp_lambda = 20 # ~1 64k sized in every 1M records
    count = 2000000
    sample = get_record_sizes(exp_lambda, count)

    f = open("ca.crt", "w")
    f.write("""-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUCiDZr7eNh+oX2Dub29D2wb1ePtswDQYJKoZIhvcNAQEL
BQAwNDEyMDAGA1UEAxMpRWxhc3RpYyBDZXJ0aWZpY2F0ZSBUb29sIEF1dG9nZW5l
cmF0ZWQgQ0EwHhcNMjExMTA4MTAyNjAwWhcNMjQxMTA3MTAyNjAwWjA0MTIwMAYD
VQQDEylFbGFzdGljIENlcnRpZmljYXRlIFRvb2wgQXV0b2dlbmVyYXRlZCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1kD6U0ti9P7BWSDpV0DO/E
X4q8uGq5SZMskDs6jenDKq8aOHj+J0ozPf6twOltJQ2SS8pjL6JTotx86zYe4KsH
emnwiOJqmw/yYxZ3jmJKK8Sqo/rD3sZqQwgSHIe9uGtlMDgaD3FGB/BAdiv/8159
sBYMaIJbpJNPDZFs/qmhJFNCWtkWmfScC3/yWlMTkDcme2tUv52VZTFpUqshtvMz
4nSePWhReD5l1LsEkAhiVc3GoyCrR9v5JRa0l81UaiQi+30vD3RVABJkhCfMzi8x
w2vX9gN5G0N68OY13C3S+3teQlLm9PU/7eGsRFxYPlJL3iRwiviLyb4W0jRc73sC
AwEAAaNTMFEwHQYDVR0OBBYEFIs6DGGHkRyTO4Q6hHr99XArJZbLMB8GA1UdIwQY
MBaAFIs6DGGHkRyTO4Q6hHr99XArJZbLMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBADPTa16qW2baS99Mx6OhivSSfilJkFWc9ipooUJvEv4K+j10
r+0qEyMu88zKHF84WEnTygJII8lW50ncPhOgbSGJEbJcz8bzA34yIFs4rs0tikzZ
M67XEx75zOW2zQOeJbiTfzhXQTJLnVzzQPnwWhE3jTG4QbEY5mFD8u7ABfemzoLj
Aqepbba91kmQvVF6jbiu8ZBe0VVJSyUSddVI98bs01BnWMOR3OmE89+sd8SRnIXa
C2FqBMXCSesYOQ7fGMpICzWeXCIIwLsi7+cUpShp9iL5Z9FU4Q/r9lgpdmssqkKF
7IPAMVhQSYUsvsPh2EJIpQB8CAgVwUkhj8fMOC8=
-----END CERTIFICATE-----""")
    f.close()

    for x in sample:
        requests.post('https://minimum-logstash-logstash:5047', data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(x)), verify = "ca.crt")

def create_messages(count, length) -> None:
    """This function is not used currently.
    """
    global MESSAGES

    longest_severity_name_len = max([len(s) for s in SEVERITIES])
    
    for s in SEVERITIES:
        MESSAGES[s] = []
        padded_s = f'{s}{" " * (longest_severity_name_len - len(s))}'
        for i in range(count):
            MESSAGES[s].append(
                f"{padded_s} msg {''.join(random.choice(LETTERS) for c in range(length))}")


def log(service_id, directory, period, log_format) -> None:
    """Create a log entry. Not used currently.
    """
    log_data = copy.deepcopy(LOG_TEMPLATE)
    log_data["service_id"] = f"lfdia_log_test_app_{service_id}"
    if directory:
        file_name = os.path.join(directory, f"{log_data['service_id']}.log")
    while True:
        log_data["timestamp"] = timestamp()
        log_data["severity"] = random.choice(SEVERITIES)
        log_data["message"] = random.choice(MESSAGES[log_data['severity']])
        log_msg = f"{json.dumps(log_data)}"
        if log_format == "text":
            log_msg = [f"{log_data.pop('timestamp')} [{log_data.pop('severity')}] message: log_data.pop('message')"]
            log_msg = [f"{k}: {log_data[k]}" for k in log_data.keys()]
            
        if directory:
            with open(file_name, "a+") as f:            
                f.write(log_msg)
                f.write("\n")
        else:
            print(log_msg)

        time.sleep(period)


def main ():
    
    parser = argparse.ArgumentParser(
        description='Append log to files in the specified directory.')
    parser.add_argument(
        "-e", "--finish_after_sec",
        help=f"Stops log generation after the specified time in seconds. If set to false, runs without time limit. Defaults to `{DEFAULT_FINISH_AFTER_SEC}'.")
    parser.add_argument(
        "-f", "--log_format", choices=['plain', 'json'],
        help=f"Format in which logs are generated. Defaults to `{DEFAULT_LOG_FORMAT}'.")
    parser.add_argument(
        "-p", "--period",
	help=f"Log generation period in seconds. Defaults to {DEFAULT_PERIOD}.")
    proc = set()
    [proc.update(v) for v in PROCESSORS.values()]
    proc = list(proc)
    parser.add_argument(
        "-r", "--processor", choices=proc,
	help=f"Define where processing happens. Subdirectory in which the logs are generated is determined based this value. Defaults to `{DEFAULT_PROCESSOR}'.")
    parser.add_argument(
        "-s", "--stack", choices=list(PROCESSORS.keys()),
	help=f"Define which stack to use. Subdirectory in which the logs are generated is dependent on this value as well. Defaults to `{DEFAULT_STACK}'.")
    parser.add_argument(
        "-S", "--size",
        help=f"Define the size of BIG logs. Defaults to `{DEFAULT_SIZE}'.")
    

    args = parser.parse_args()
        
    if args.period:
        period = float(args.period)
    else:
        period = float(os.environ.get('PERIOD', DEFAULT_PERIOD))
        
    if args.log_format:
        log_format = args.log_format
    else:
        log_format = os.environ.get('LOG_FORMAT', DEFAULT_LOG_FORMAT)

    if args.processor:
        processor = args.processor
    else:
        processor = os.environ.get('PROCESSOR', DEFAULT_PROCESSOR)

    if args.stack:
        stack = args.stack
    else:
        stack = os.environ.get('STACK', DEFAULT_STACK)

    if args.finish_after_sec:
        finish_after_sec = float(args.finish_after_sec)
    else:
        finish_after_sec = float(os.environ.get('FINISH_AFTER_SEC', DEFAULT_FINISH_AFTER_SEC))
        
    if args.size:
        size = int(args.size)
    else:
        size = int(os.environ.get('SIZE', DEFAULT_SIZE))

    if processor not in PROCESSORS[stack]:
        print(f"Invalid combination of stack `{stack}' and processor `{processor}'... exiting")
        return

    log_dir = os.path.join("./logs", stack)

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    start_time = time.time()
    tag_random = random.randint(0, 99999)
    k = 'Big'
    
    done = False
    
    while True:
        if done:
            time.sleep(period)
        else:
            send_log()
            done = True

if __name__ == '__main__':
    main()
