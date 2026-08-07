#!/usr/bin/env python3
"""Shared correlation notes/utilities for Scenario 19.
The main executable logic is in local_rule_evaluator.py. This module deliberately remains small so correlation semantics stay auditable.
"""
from datetime import datetime, timedelta

def parse_time(value): return datetime.fromisoformat(value.replace('Z','+00:00'))
def within(after, before, seconds):
    a,b=parse_time(after),parse_time(before)
    return b <= a <= b+timedelta(seconds=seconds)
